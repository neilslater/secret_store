# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Store do
  let(:directory) { Dir.mktmpdir('secret-store-races') }
  let(:path) { File.join(directory, 'store.dat') }
  let(:first) { described_class.new(path) }
  let(:second) { described_class.new(path) }

  before do
    first
    second.db.busy_timeout(0)
  end

  after do
    first.db.close
    second.db.close
    FileUtils.remove_entry(directory)
  end

  def while_writer_paused
    barrier = ThreadBarrier.new
    operation = lambda do
      first.transaction do
        barrier.pause
        yield
      end
    end
    barrier.run(operation) { expect { second.save_secret(primary_secret) }.to raise_error(SQLite3::BusyException) }
  end

  def compete_initial_connections
    barrier = ThreadBarrier.new
    pause_password_load(barrier)
    barrier.run(-> { SecretStore::Connection.new(first, example_password) }) do
      expect { SecretStore::Connection.new(second, 'another-password') }.to raise_error(SQLite3::BusyException)
    end
  end

  def pause_password_load(barrier)
    allow(first).to receive(:load_password).and_wrap_original do |original|
      barrier.pause
      original.call
    end
  end

  it 'configures a bounded five-second busy timeout' do
    expect(first.db.get_first_value('PRAGMA busy_timeout')).to eq(5000)
  end

  it 'serializes competing inserts and leaves a usable handle after busy failure', :aggregate_failures do
    while_writer_paused { first.save_secret(primary_secret) }
    second.save_secret(secondary_secret)
    expect(first.all_secrets.map(&:label)).to contain_exactly('example', 'second')
    expect(second.db.transaction_active?).to be(false)
  end

  it 'upserts the same label without duplicates after contention', :aggregate_failures do
    while_writer_paused { first.save_secret(primary_secret) }
    second.save_secret(primary_secret)
    expect(first.all_secrets.map(&:to_h)).to eq([primary_secret.to_h])
  end

  it 'serializes initial connection attempts without replacing the winning password', :aggregate_failures do
    compete_initial_connections
    expect { SecretStore::Connection.new(second, 'another-password') }.to raise_error(/Incorrect password/)
    expect(second.load_password.activate_checksum(example_password)).to be_a(String)
  end
end
