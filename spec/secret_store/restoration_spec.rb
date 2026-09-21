# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Restoration do
  let(:directory) { Dir.mktmpdir('secret-store-restore') }
  let(:destination) { File.join(directory, 'destination.dat') }
  let(:yaml_path) { File.join(directory, 'input.yml') }
  let(:data) { YAML.safe_load_file(yaml_fixture, permitted_classes: [Symbol]) }

  let(:opened) { [] }

  before do
    allow(SecretStore::Store).to receive(:new).and_wrap_original do |original, *args|
      original.call(*args).tap { |store| opened << store }
    end
  end

  after do
    opened.each { |store| store.db.close unless store.db.closed? }
    FileUtils.remove_entry(directory)
  end

  def write_archive(value = data)
    File.write(yaml_path, YAML.dump(value))
    yaml_path
  end

  def import
    SecretStore::Store.import_yaml(yaml_path, destination)
  end

  def connect(password = example_password)
    SecretStore::Connection.init_from_yaml(destination, password, yaml_path)
  end

  def expect_preflight_failure
    expect { import }.to raise_error(SecretStore::FormatError)
    expect(File.exist?(destination)).to be(false)
    expect(opened).to be_empty
  end

  describe 'preflight' do
    [nil, [], 42, 'archive'].each do |value|
      it "rejects a #{value.class} envelope before opening a destination", :aggregate_failures do
        write_archive(value)
        expect_preflight_failure
      end
    end

    [nil, {}, 'records'].each do |value|
      it "rejects a #{value.class} secrets container", :aggregate_failures do
        write_archive(data.merge(secrets: value))
        expect_preflight_failure
      end
    end

    it 'rejects string keys instead of silently restoring an empty archive', :aggregate_failures do
      write_archive('secrets' => data[:secrets])
      expect_preflight_failure
    end

    it 'rejects duplicate labels', :aggregate_failures do
      write_archive(data.merge(secrets: [data[:secrets].first, data[:secrets].first.transform_values(&:dup)]))
      expect_preflight_failure
    end

    [nil, {}].each do |value|
      it 'rejects orphan secrets', :aggregate_failures do
        write_archive(data.merge(master_password: value))
        expect_preflight_failure
      end
    end

    [{ auth_tag: nil }, { auth_tag: 'dA==' }, { iv: '!' }, { pbkdf2_salt: 'c2hvcnQ=' }].each do |invalid|
      it 'rejects a late malformed record without partial installation', :aggregate_failures do
        data[:secrets][1].merge!(invalid)
        write_archive
        expect_preflight_failure
      end
    end

    it 'rejects a missing field in a late record', :aggregate_failures do
      data[:secrets][1].delete(:crypted_text)
      write_archive
      expect_preflight_failure
    end
  end

  describe 'empty archives' do
    [{}, { master_password: {} }, { master_password: nil, secrets: [] }].each do |value|
      it 'supports historical empty representations', :aggregate_failures do
        write_archive(value)
        expect(import).to be_empty
      end
    end

    it 'round-trips an actual blank-store export with canonical null password', :aggregate_failures do
      SecretStore::Store.new(':memory:').export_yaml(yaml_path)
      expect(YAML.safe_load_file(yaml_path, permitted_classes: [Symbol]))
        .to eq(master_password: nil, secrets: [])
      expect(import).to be_empty
    end

    it 'prepares a new password before installing an empty connection archive' do
      write_archive({})
      expect(connect.all_secret_labels).to eq([])
    end

    [nil, 'short'].each do |password|
      it 'rejects invalid new passwords without creating a destination', :aggregate_failures do
        write_archive({})
        expect { connect(password) }.to raise_error(/Password too short/)
        expect(File.exist?(destination)).to be(false)
      end
    end
  end

  describe 'destination protection' do
    it 'rejects a password-only destination unchanged', :aggregate_failures do
      SecretStore::Store.new(destination).save_password(fixture_password)
      write_archive
      original = File.binread(destination)
      expect { import }.to raise_error(/empty destination/)
      expect(File.binread(destination)).to eq(original)
    end

    it 'rejects a destination containing orphan secrets', :aggregate_failures do
      SecretStore::Store.new(destination).save_secret(primary_secret)
      write_archive
      original = File.binread(destination)
      expect { import }.to raise_error(/empty destination/)
      expect(File.binread(destination)).to eq(original)
    end

    [false, true].each do |existing|
      it "rejects wrong passwords without changing an #{existing ? 'existing' : 'absent'} path", :aggregate_failures do
        FileUtils.cp(sqlite_fixture, destination) if existing
        original = File.binread(destination) if existing
        write_archive
        expect { connect('wrong-password') }.to raise_error(/Incorrect password/)
        expect(existing ? File.binread(destination) : File.exist?(destination)).to eq(existing ? original : false)
      end

      it "rejects corrupt ciphertext before opening an #{existing ? 'existing' : 'absent'} path", :aggregate_failures do
        FileUtils.cp(sqlite_fixture, destination) if existing
        data[:secrets][1][:crypted_text] = flip_last_cipher_bit(data[:secrets][1][:crypted_text])
        write_archive
        expect { connect }.to raise_error(OpenSSL::Cipher::CipherError)
        expect(opened).to be_empty
      end
    end

    it 'documents the password-free authentication boundary', :aggregate_failures do
      data[:secrets][1][:crypted_text] = flip_last_cipher_bit(data[:secrets][1][:crypted_text])
      write_archive
      restored = import
      expect { restored.load_secret('second').decrypt_text(example_checksum) }.to raise_error(OpenSSL::Cipher::CipherError)
    end
  end

  describe 'open failures' do
    it 'propagates an invalid destination error without leaking a handle' do
      write_archive
      expect { described_class.read(yaml_path).restore(File.join(directory, 'missing', 'file')) }
        .to raise_error(SQLite3::CantOpenException)
    end

    it 'closes a handle whose schema initialization fails' do
      File.write(destination, 'not a SQLite database')
      expect { SecretStore::Connection.load(destination, example_password) }.to raise_error(SQLite3::NotADatabaseException)
    end
  end

  describe 'atomic installation' do
    def install_failure_trigger
      store = SecretStore::Store.new(destination)
      store.db.execute <<~SQL
        CREATE TRIGGER reject_second BEFORE INSERT ON secret WHEN NEW.label = 'second'
        BEGIN SELECT RAISE(ABORT, 'injected failure'); END;
      SQL
    end

    it 'rolls back a late SQL failure and closes the import handle', :aggregate_failures do
      install_failure_trigger
      write_archive
      expect { import }.to raise_error(SQLite3::ConstraintException)
      expect(opened.last.db).to be_closed
      expect(opened.first).to be_empty
    end

    it 'can retry successfully after a failed installation', :aggregate_failures do
      install_failure_trigger
      write_archive
      expect { import }.to raise_error(SQLite3::ConstraintException)
      opened.first.db.execute('DROP TRIGGER reject_second')
      expect(import.all_secrets.map(&:to_h)).to eq(data[:secrets])
    end

    def competing_imports(barrier)
      prepare_competing_stores(barrier)
      barrier.run(-> { import }) { expect { import }.to raise_error(SQLite3::BusyException) }
    end

    def prepare_competing_stores(barrier)
      first = SecretStore::Store.new(destination)
      second = SecretStore::Store.new(destination)
      second.db.busy_timeout(0)
      allow(SecretStore::Store).to receive(:new).with(destination).and_return(first, second)
      pause_empty_check(first, barrier)
    end

    def pause_empty_check(store, barrier)
      allow(store).to receive(:empty?).and_wrap_original do |original|
        barrier.pause
        original.call
      end
    end

    it 'prevents simultaneous imports from combining records', :aggregate_failures do
      write_archive
      competing_imports(ThreadBarrier.new)
      expect(opened.first.all_secrets.map(&:to_h)).to eq(data[:secrets])
      expect(opened.last.db).to be_closed
    end
  end
end
