# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Connection do
  describe 'class methods' do
    describe '#new' do
      it 'rejects objects which are not stores' do
        expect do
          described_class.new(Object.new, example_password)
        end.to raise_error RuntimeError, /Expected a SecretStore::Store/
      end

      it 'connects to an existing store file' do
        connection = described_class.new(memory_store_fixture, example_password)
        expect(connection).to be_a described_class
      end

      it 'fails to connect if the password is bad' do
        expect do
          described_class.new(memory_store_fixture, 'wrong')
        end.to raise_error RuntimeError, /password/
      end

      it 'allows a new password on a new blank store' do
        store = SecretStore::Store.new(':memory:')
        described_class.new(store, 'another-password')
        expect(store.load_password.activate_checksum('another-password')).to be_truthy
      end

      it 'rejects a short password for a new store' do
        expect do
          described_class.new(SecretStore::Store.new(':memory:'), 'short')
        end.to raise_error RuntimeError, /Password too short/
      end
    end

    describe '#load' do
      it 'connects to an existing store file' do
        connection = described_class.load(sqlite_fixture, example_password)
        expect(connection).to be_a described_class
      end

      it 'fails to connect if the password is bad' do
        expect do
          described_class.load(sqlite_fixture, 'wrong')
        end.to raise_error RuntimeError, /password/
      end

      it 'allows a new password on a new blank store' do
        connection = described_class.load(':memory:', 'another-password')
        expect(connection.store.load_password.activate_checksum('another-password')).to be_truthy
      end
    end

    describe '#init_from_yaml' do
      it 'generates a new store and populates with YAML data', :aggregate_failures do
        connection = described_class.init_from_yaml(':memory:', example_password, yaml_fixture)
        expect(connection).to be_a described_class
        expect(connection.all_secret_labels).to match_array %w[example second]
      end

      it 'fails to import and connect if the password is bad' do
        expect do
          described_class.init_from_yaml(':memory:', 'wrong-password', yaml_fixture)
        end.to raise_error RuntimeError, /password/
      end
    end
  end

  describe 'instance methods' do
    subject(:connection) { described_class.init_from_yaml(':memory:', example_password, yaml_fixture) }

    def num_secrets_in(database)
      database.execute('SELECT count(*) FROM secret').first.first
    end

    describe '#write_secret' do
      it 'adds a new secret to the database, if the label is new' do
        database = connection.store.db
        expect do
          connection.write_secret 'new_label', 'New message'
        end.to change { num_secrets_in(database) }.by 1
      end

      it 'adds the new secret so that it can be decrypted' do
        connection.write_secret 'new_label', 'New message'
        expect(connection.store.load_secret('new_label').decrypt_text(example_checksum)).to eql 'New message'
      end

      it 'over-writes an existing secret', :aggregate_failures do
        expect(connection.store.load_secret('example').decrypt_text(example_checksum)).to eql primary_plaintext
        connection.write_secret 'example', 'New message'
        expect(connection.store.load_secret('example').decrypt_text(example_checksum)).to eql 'New message'
        database = connection.store.db
        expect(num_secrets_in(database)).to be 2
      end
    end

    describe '#read_secret' do
      it 'decrypts secret from database', :aggregate_failures do
        expect(connection.read_secret('example')).to eql primary_plaintext
        expect(connection.read_secret('second')).to eql secondary_plaintext
      end
    end

    describe '#delete_secret' do
      it 'removes secret from database', :aggregate_failures do
        connection.delete_secret 'example'
        expect(connection.read_secret('example')).to be_nil
        expect(connection.read_secret('second')).to eql secondary_plaintext
      end
    end

    describe '#all_secret_labels' do
      it 'lists all known labels', :aggregate_failures do
        expect(connection.all_secret_labels).to match_array %w[example second]
        connection.write_secret 'third', 'Third secret message'
        expect(connection.all_secret_labels).to match_array %w[example second third]
      end
    end

    describe '#change_password' do
      it 'rejects a short new password' do
        expect do
          connection.change_password 'short'
        end.to raise_error RuntimeError, /Password too short/
      end

      it 'still allows reading current secrets', :aggregate_failures do
        connection.change_password 'super-secret'
        expect(connection.read_secret('example')).to eql primary_plaintext
        expect(connection.read_secret('second')).to eql secondary_plaintext
      end

      it 'rejects the old password after a change' do
        connection.change_password 'super-secret'
        expect do
          described_class.new(connection.store, example_password)
        end.to raise_error RuntimeError, /password/
      end

      it 'accepts the new password after a change' do
        connection.change_password 'super-secret'
        reconnected = described_class.new(connection.store, 'super-secret')
        expect([reconnected.read_secret('example'), reconnected.read_secret('second')])
          .to eql [primary_plaintext, secondary_plaintext]
      end
    end
  end
end
