# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::BackupFile do
  let(:directory) { Dir.mktmpdir('secret-store-backup') }
  let(:database_path) { File.join(directory, 'store.dat') }
  let(:backup_path) { File.join(directory, 'backup with spaces.yml') }
  let(:store) do
    FileUtils.cp(sqlite_fixture, database_path)
    SecretStore::Store.new(database_path)
  end

  after do
    store.db.close
    FileUtils.remove_entry(directory)
  end

  def assert_collision(path)
    original = File.binread(database_path)
    expect { store.export_yaml(path) }.to raise_error(RuntimeError, /destination/)
    expect(File.binread(database_path)).to eq(original)
    expect_readable_store
  end

  def expect_readable_store
    expect(store.load_secret('example').decrypt_text(example_checksum)).to eq(primary_plaintext)
  end

  describe 'database collisions' do
    before { store }

    it 'rejects the exact database filename', :aggregate_failures do
      assert_collision(database_path)
    end

    it 'rejects an equivalent relative path', :aggregate_failures do
      Dir.chdir(directory) { assert_collision('./store.dat') }
    end

    it 'rejects symlink targets', :aggregate_failures do
      File.symlink(database_path, backup_path)
      assert_collision(backup_path)
    end

    it 'rejects hard-link aliases', :aggregate_failures do
      File.link(database_path, backup_path)
      assert_collision(backup_path)
    end

    it 'resolves symlinked parent directories', :aggregate_failures do
      File.symlink(directory, File.join(directory, 'alias'))
      assert_collision(File.join(directory, 'alias', 'store.dat'))
    end

    %w[-journal -wal -shm].each do |suffix|
      it "rejects the #{suffix} sidecar path even when absent", :aggregate_failures do
        assert_collision(database_path + suffix)
      end
    end

    it 'rejects hard links to SQLite sidecars', :aggregate_failures do
      store.db.execute('PRAGMA journal_mode=WAL')
      store.save_secret(primary_secret)
      File.link("#{database_path}-wal", backup_path)
      assert_collision(backup_path)
    end

    it 'protects attached database files too', :aggregate_failures do
      store.db.execute('ATTACH DATABASE ? AS extra', [backup_path])
      assert_collision(backup_path)
    end
  end

  describe 'publication' do
    before do
      store
      File.write(backup_path, 'previous backup')
    end

    def expect_preserved_backup
      expect { store.export_yaml(backup_path) }.to raise_error(IOError)
      expect(File.read(backup_path)).to eq('previous backup')
      expect(Dir.glob(File.join(directory, '.secret-store-*'))).to be_empty
    end

    def fail_file_operation(operation)
      allow(Tempfile).to receive(:create).and_wrap_original do |original, *args, &block|
        original.call(*args) do |file|
          inject_file_failure(file, operation)
          block.call(file)
        end
      end
    end

    def inject_file_failure(file, operation)
      allow(file).to receive(operation).and_wrap_original do |original, *args|
        args[0] = args[0][0, 5] if operation == :write
        original.call(*args)
        raise IOError, 'injected file failure'
      end
    end

    %i[write flush fsync close].each do |operation|
      it "preserves the old backup and removes temporary files on #{operation} failure", :aggregate_failures do
        fail_file_operation(operation)
        expect_preserved_backup
      end
    end

    it 'preserves the old backup on serialization failure', :aggregate_failures do
      allow(YAML).to receive(:dump).and_raise(IOError)
      expect_preserved_backup
    end

    it 'preserves the old backup on rename failure', :aggregate_failures do
      allow(File).to receive(:rename).and_raise(IOError)
      expect_preserved_backup
    end

    it 'replaces a regular backup with a complete private file', :aggregate_failures do
      store.export_yaml(backup_path)
      expect(File.stat(backup_path).mode & 0o777).to eq(0o600)
      expect(YAML.safe_load_file(backup_path, permitted_classes: [Symbol])[:secrets]).to eq([primary_secret.to_h])
    end

    it 'rejects files owned by someone else' do
      stat = File.stat(backup_path)
      allow(stat).to receive(:uid).and_return(Process.euid + 1)
      allow(File).to receive(:lstat).and_call_original
      allow(File).to receive(:lstat).with(File.realpath(backup_path)).and_return(stat)
      expect { store.export_yaml(backup_path) }.to raise_error(/owned by the current user/)
    end
  end

  describe 'other targets' do
    it 'rejects a missing parent directory' do
      expect { store.export_yaml(File.join(directory, 'missing', 'backup.yml')) }.to raise_error(Errno::ENOENT)
    end

    it 'rejects directories' do
      expect { store.export_yaml(directory) }.to raise_error(/regular file/)
    end

    it 'rejects FIFOs without opening them' do
      File.mkfifo(backup_path)
      expect { store.export_yaml(backup_path) }.to raise_error(/regular file/)
    end

    it 'supports memory stores and preserves the nil return value', :aggregate_failures do
      memory = SecretStore::Store.new(':memory:')
      expect(memory.export_yaml(backup_path)).to be_nil
      expect(File.stat(backup_path).mode & 0o777).to eq(0o600)
      memory.db.close
    end
  end

  describe 'snapshot consistency' do
    def pause_after_password(barrier)
      allow(store).to receive(:load_password).and_wrap_original do |original|
        password = original.call
        barrier.pause
        password
      end
    end

    def rotate_during_snapshot
      store.db.execute('PRAGMA journal_mode=WAL')
      barrier = ThreadBarrier.new
      pause_after_password(barrier)
      with_writer do |writer|
        barrier.run(-> { store.export_yaml(backup_path) }) { writer.change_password('replacement-password') }
      end
    end

    def with_writer
      writer = SecretStore::Connection.load(database_path, example_password)
      yield writer
    ensure
      writer.store.db.close if writer
    end

    it 'exports one coherent generation while another handle rotates', :aggregate_failures do
      rotate_during_snapshot
      restored = SecretStore::Connection.init_from_yaml(':memory:', example_password, backup_path)
      expect(restored.read_secret('example')).to eq(primary_plaintext)
      expect { SecretStore::Connection.load(database_path, example_password) }.to raise_error(/Incorrect password/)
      restored.store.db.close
    end
  end
end
