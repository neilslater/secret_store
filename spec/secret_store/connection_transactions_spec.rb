# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Connection do
  let(:directory) { Dir.mktmpdir('secret-store-transactions') }
  let(:path) { File.join(directory, 'store.dat') }
  let(:store) do
    FileUtils.cp(sqlite_fixture, path)
    database = SecretStore::Store.new(path)
    database.save_secret(secondary_secret)
    database
  end
  let(:connection) { described_class.new(store, example_password) }

  after do
    store.db.close
    FileUtils.remove_entry(directory)
  end

  def rows
    [store.db.execute('SELECT * FROM master_password'), store.db.execute('SELECT * FROM secret ORDER BY label')]
  end

  def reject_update(table, condition = '1')
    store.db.execute <<~SQL
      CREATE TRIGGER reject_update BEFORE UPDATE ON #{table} WHEN #{condition}
      BEGIN SELECT RAISE(ABORT, 'injected SQL failure'); END;
    SQL
  end

  def expect_failed_rotation(error)
    original = rows
    expect { connection.change_password('replacement-password') }.to raise_error(error)
    expect(rows).to eq(original)
    expect_original_session
  end

  def expect_original_session
    expect(connection.read_secret('example')).to eq(primary_plaintext)
    expect(store.db.transaction_active?).to be(false)
  end

  describe '#change_password' do
    before { connection }

    it 'rolls back a later secret update failure', :aggregate_failures do
      reject_update('secret', "NEW.label = 'second'")
      expect_failed_rotation(SQLite3::ConstraintException)
    end

    it 'rolls back a later authentication failure', :aggregate_failures do
      store.db.execute('UPDATE secret SET crypted_text = ? WHERE label = ?',
                       [flip_last_cipher_bit(secondary_secret.crypted_text), 'second'])
      expect_failed_rotation(OpenSSL::Cipher::CipherError)
    end

    it 'rolls back a password save failure', :aggregate_failures do
      reject_update('master_password')
      expect_failed_rotation(SQLite3::ConstraintException)
    end

    it 'rolls back a failed commit without changing the session', :aggregate_failures do
      allow(store.db).to receive(:commit) do
        allow(store.db).to receive(:commit).and_call_original
        raise SQLite3::BusyException
      end
      expect_failed_rotation(SQLite3::BusyException)
    end

    it 'rolls back a later encryption failure', :aggregate_failures do
      allow(SecretStore::Secret).to receive(:create_from_plaintext).and_wrap_original do |original, *args|
        raise OpenSSL::Cipher::CipherError if args[0] == 'second'

        original.call(*args)
      end
      expect_failed_rotation(OpenSSL::Cipher::CipherError)
    end

    it 'rotates a password-only store', :aggregate_failures do
      store.db.execute('DELETE FROM secret')
      connection.change_password('replacement-password')
      reopened = described_class.load(path, 'replacement-password')
      expect(reopened.all_secret_labels).to eq([])
      reopened.store.db.close
    end
  end

  describe 'stale sessions' do
    let(:other) { described_class.load(path, example_password) }

    before do
      connection
      other
      connection.change_password('replacement-password')
    end

    after { other.store.db.close }

    [[:write_secret, 'new', 'value'], [:delete_secret, 'example'], [:change_password, 'another-password'],
     [:read_secret, 'example'], [:all_secret_labels]].each do |operation|
      it "rejects stale #{operation.first} without mutation", :aggregate_failures do
        original = rows
        expect { other.public_send(*operation) }.to raise_error(/reconnect required/)
        expect(rows).to eq(original)
        expect(connection.read_secret('example')).to eq(primary_plaintext)
      end
    end

    it 'rejects a removed master password' do
      store.db.execute('DELETE FROM master_password')
      expect { connection.read_secret('example') }.to raise_error(/reconnect required/)
    end
  end

  def abort_transaction(reason)
    store.transaction do
      store.delete_secret('example')
      reason == :cancel ? throw(:cancel) : raise(reason)
    end
  end

  describe 'transaction ownership' do
    it 'rejects nested work without rolling back the caller transaction', :aggregate_failures do
      connection
      store.db.transaction
      expect { connection.write_secret('new', 'value') }.to raise_error(/Nested transactions/)
      expect(store.db.transaction_active?).to be(true)
      store.db.rollback
    end

    it 'rolls back interruption', :aggregate_failures do
      expect { abort_transaction(Interrupt) }.to raise_error(Interrupt)
      expect(store.load_secret('example')).not_to be_nil
      expect(store.db.transaction_active?).to be(false)
    end

    it 'rolls back nonlocal exits', :aggregate_failures do
      catch(:cancel) { abort_transaction(:cancel) }
      expect(store.load_secret('example')).not_to be_nil
      expect(store.db.transaction_active?).to be(false)
    end

    it 'rejects orphan secrets without installing a password', :aggregate_failures do
      store.db.execute('DELETE FROM master_password')
      expect { described_class.new(store, example_password) }.to raise_error(/secrets without a master password/)
      expect(store.load_password).to be_nil
    end
  end
end
