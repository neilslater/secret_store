# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tempfile'

describe SecretStore::Store do
  describe 'class methods' do
    describe '#new' do
      it 'creates valid store from scratch' do
        store = described_class.new(':memory:')
        expect(store).to be_a described_class
      end

      it 'preserves the password in an existing store', :aggregate_failures do
        store = described_class.new(sqlite_fixture)
        password = store.load_password
        expect(password).to be_a SecretStore::Password
        expect(password.activate_checksum(example_password)).to eql example_checksum
      end

      it 'preserves secrets in an existing store', :aggregate_failures do
        store = described_class.new(sqlite_fixture)
        secret = store.load_secret('example')
        expect(secret).to be_a SecretStore::Secret
        expect(secret.decrypt_text(example_checksum)).to eql primary_plaintext
      end
    end

    describe '#import_yaml' do
      it 'creates a new store' do
        store = described_class.import_yaml(yaml_fixture, ':memory:')
        expect(store).to be_a described_class
      end

      it 'imports data correctly', :aggregate_failures do
        store = described_class.import_yaml(yaml_fixture, ':memory:')
        expect(store.load_password.activate_checksum(example_password)).to eql example_checksum
        expect(store.load_secret('example').to_h).to eql primary_secret.to_h
        expect(store.load_secret('second').to_h).to eql secondary_secret.to_h
      end

      it 'accepts an empty export', :aggregate_failures do
        store = empty_yaml_store
        expect(store.load_password).to be_nil
        expect(store.all_secrets).to be_empty
      end
    end
  end

  describe 'instance methods' do
    subject(:store) { described_class.new(':memory:') }

    def db_num_secrets
      store.db.execute('SELECT count(*) FROM secret').first.first
    end

    def db_num_passwords
      store.db.execute('SELECT count(*) FROM master_password').first.first
    end

    describe '#save_password' do
      it 'writes password data to database' do
        expect { store.save_password fixture_password }
          .to change { db_num_passwords }.from(0).to(1)
      end

      it 'is idempotent' do
        expect { 5.times { store.save_password fixture_password } }
          .to change { db_num_passwords }.from(0).to(1)
      end
    end

    describe '#load_password' do
      it 'returns nil when there is no password' do
        expect(store.load_password).to be_nil
      end

      it 'returns password data when there is one' do
        store.save_password fixture_password
        password_from_store = store.load_password
        expect(password_from_store.to_h).to eql fixture_password.to_h
      end
    end

    describe '#save_secret' do
      it 'adds new secret to database' do
        expect { store.save_secret(primary_secret) }
          .to change { db_num_secrets }.from(0).to(1)
      end

      it 'is idempotent' do
        expect { 5.times { store.save_secret(primary_secret) } }
          .to change { db_num_secrets }.from(0).to(1)
      end

      it 'adds new secrets indexed by the label' do
        expect do
          store.save_secret(primary_secret)
          store.save_secret(secondary_secret)
        end.to change { db_num_secrets }.from(0).to(2)
      end
    end

    describe '#load_secret' do
      it 'returns nil when there is no secret with matching label', :aggregate_failures do
        expect(store.load_secret('example')).to be_nil
        store.save_secret(primary_secret)
        expect(store.load_secret('anything_else')).to be_nil
      end

      it 'returns valid secrets when extracted by label', :aggregate_failures do
        store.save_secret(primary_secret)
        store.save_secret(secondary_secret)
        loaded_secrets = [store.load_secret('example'), store.load_secret('second')]
        expect(loaded_secrets).to all be_a SecretStore::Secret
        expect(decrypted_texts(loaded_secrets)).to eql [primary_plaintext, secondary_plaintext]
      end
    end

    describe '#delete_secret' do
      before do
        store.save_secret(primary_secret)
        store.save_secret(secondary_secret)
      end

      it 'makes no difference when there is no matching label', :aggregate_failures do
        store.delete_secret('qwerty')
        loaded_secrets = [store.load_secret('example'), store.load_secret('second')]
        expect(db_num_secrets).to be 2
        expect(loaded_secrets).to all be_a SecretStore::Secret
        expect(decrypted_texts(loaded_secrets)).to eql [primary_plaintext, secondary_plaintext]
      end

      it 'removes an existing secret without affecting others', :aggregate_failures do
        store.delete_secret('example')
        remaining_secret = store.load_secret('second')
        expect([db_num_secrets, store.load_secret('example')]).to eql [1, nil]
        expect([remaining_secret.class, remaining_secret.decrypt_text(example_checksum)])
          .to eql [SecretStore::Secret, secondary_plaintext]
      end
    end

    describe '#export_yaml' do
      let(:yaml_file) { Tempfile.new('secret_store_test.yml').tap(&:close).path }
      let(:fixture_store) { described_class.new(sqlite_fixture) }

      before { FileUtils.rm_f(yaml_file) }
      after { FileUtils.rm_f(yaml_file) }

      it 'writes a file' do
        fixture_store.export_yaml(yaml_file)
        expect(File.size?(yaml_file)).to be > 200
      end

      it 'saves YAML data to the file' do
        fixture_store.export_yaml(yaml_file)
        exported_data = YAML.safe_load_file(yaml_file, permitted_classes: [Symbol])
        expect(exported_data).to eql({ master_password: { bcrypt_salt: example_bcrypt_salt,
                                                          pbkdf2_salt: example_pbkdf_salt,
                                                          test_encryption: example_cipher },
                                       secrets: [primary_secret.to_h] })
      end
    end

    describe '#all_secrets' do
      it 'returns empty array when there are no secrets in the store' do
        expect(store.all_secrets).to be_empty
      end

      it 'returns array of all secrets in the store', :aggregate_failures do
        store.save_secret(primary_secret)
        store.save_secret(secondary_secret)
        stored_secrets = store.all_secrets.sort_by(&:label)
        expect(stored_secrets).to all be_a SecretStore::Secret
        expect(decrypted_texts(stored_secrets)).to eql [primary_plaintext, secondary_plaintext]
      end
    end
  end
end
