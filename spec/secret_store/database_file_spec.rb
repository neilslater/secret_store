# frozen_string_literal: true

require 'spec_helper'
require 'pathname'

describe SecretStore::DatabaseFile do
  let(:directory) { Dir.mktmpdir('secret-store-private') }
  let(:path) { File.join(directory, 'private store.dat') }
  let(:opened) { [] }

  around do |example|
    previous = File.umask(0o022)
    example.run
  ensure
    File.umask(previous)
  end

  after do
    opened.each { |store| store.db.close unless store.db.closed? }
    FileUtils.remove_entry(directory)
  end

  def open_store(filename = path)
    SecretStore::Store.new(filename).tap { |store| opened << store }
  end

  def mode(filename)
    File.stat(filename).mode & 0o777
  end

  it 'creates private database files under a permissive umask', :aggregate_failures do
    open_store
    expect(mode(path)).to eq(0o600)
    expect(File.umask).to eq(0o022)
  end

  it 'keeps newly created stores and exports usable under a restrictive umask' do
    directory
    File.umask(0o777)
    open_store.export_yaml(File.join(directory, 'backup.yml'))
    expect([mode(path), mode(File.join(directory, 'backup.yml'))]).to eq([0o600, 0o600])
  end

  it 'leaves pre-existing broad file permissions unchanged' do
    File.write(path, '')
    File.chmod(0o644, path)
    open_store
    expect(mode(path)).to eq(0o644)
  end

  it 'supports Pathname arguments' do
    expect(open_store(Pathname.new(path))).to be_empty
  end

  it 'supports pre-existing symlinks without changing target permissions' do
    File.write(path, '')
    File.symlink(path, File.join(directory, 'alias'))
    open_store(File.join(directory, 'alias'))
    expect(mode(path)).to eq(0o644)
  end

  it 'rejects dangling symlinks without creating the target', :aggregate_failures do
    File.symlink(File.join(directory, 'missing'), path)
    expect { open_store }.to raise_error(ArgumentError, /regular file/)
    expect(File.exist?(File.join(directory, 'missing'))).to be(false)
  end

  it 'rejects SQLite URI strings explicitly' do
    expect { open_store("file:#{path}?mode=rwc") }.to raise_error(ArgumentError, /ordinary filename/)
  end

  [':memory:', ''].each do |filename|
    it 'preserves SQLite memory/temporary database behavior' do
      expect(open_store(filename)).to be_empty
    end
  end

  it 'creates private rollback journals', :aggregate_failures do
    store = open_store
    store.transaction do
      store.save_secret(primary_secret)
      expect(mode("#{path}-journal")).to eq(0o600)
    end
  end

  it 'creates private WAL and shared-memory sidecars', :aggregate_failures do
    store = open_store
    store.db.execute('PRAGMA journal_mode=WAL')
    store.save_secret(primary_secret)
    expect([mode("#{path}-wal"), mode("#{path}-shm")]).to eq([0o600, 0o600])
  end

  it 'cooperates with an already-created file during concurrent initialization', :aggregate_failures do
    described_class.prepare(path)
    first = open_store
    second = open_store
    first.save_secret(primary_secret)
    expect(second.load_secret('example').to_h).to eq(primary_secret.to_h)
  end
end
