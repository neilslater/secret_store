# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tempfile'

describe SecretStore::Store do
  let(:example_password_text) { 'QwertyUiop' }
  let(:example_bcrypt_salt) { '$2a$14$.WO3JtKxNhzlASL4eQpkEO' }
  let(:example_pbkdf_salt) { 'rCLPwKKsFb5WwgY1y0LwAQ==' }
  let(:example_cipher) do
    '9_ZGG1_mabi9Q5qvxu4sOA== ~ k4TSdX28eTImvdDmzhtju-87-35msJBPilU_25JG6UE= ~ dKxORrEkMFsW_uAsr3fGHA=='
  end

  let(:example_password) { SecretStore::Password.new(example_bcrypt_salt, example_pbkdf_salt, example_cipher) }
  let(:example_checksum) { '3EG3i1.oq1T5cmZVlq.cnOt28gz6U8G' }

  let(:example_secret_1) do
    SecretStore::Secret.new('example', 'u0CAnSPnSbN1sVi03_ck4A==', 'yLIp8f6eeIzxOEvA1-uzbw==',
                            'IWYGh4x98_4Flk_1OrhvaaI=', 'szbH9SG0pymGCpU3lkIWNA==')
  end
  let(:example_plaintext_1) { 'This is a secret!' }

  let(:example_secret_2) do
    SecretStore::Secret.new('second', '_Ra_07_YwLgOlgFXxBh7Xg==', 'xTmbPzciYuTNa8MVIBzcVQ==',
                            'aLA1CoQz0beM8NrC_mAdtru_cmHod0Gv', 'WOLMoGcQdPl8hayLX9M4JQ==')
  end
  let(:example_plaintext_2) { 'This is a second secret!' }

  describe 'class methods' do
    describe '#new' do
      it 'creates valid store from scratch' do
        store = described_class.new(':memory:')
        expect(store).to be_a described_class
      end

      it 'creates valid store from existing file without deleting anything' do
        store = described_class.new(File.join(File.dirname(__FILE__), 'fixture_store.dat'))
        expect(store).to be_a described_class
        pw = store.load_password
        expect(pw).to be_a SecretStore::Password
        expect(pw.activate_checksum(example_password_text)).to eql example_checksum
        secret = store.load_secret('example')
        expect(secret).to be_a SecretStore::Secret
        expect(secret.decrypt_text(example_checksum)).to eql example_plaintext_1
      end
    end

    describe '#import_yaml' do
      let(:yaml_fixture) { File.join(File.dirname(__FILE__), 'fixture_store.yml') }

      it 'creates a new store' do
        store = described_class.import_yaml(yaml_fixture, ':memory:')
        expect(store).to be_a described_class
      end

      it 'imports data correctly' do
        store = described_class.import_yaml(yaml_fixture, ':memory:')
        expect(store.load_password.activate_checksum(example_password_text)).to eql example_checksum
        expect(store.load_secret('example').to_h).to eql example_secret_1.to_h
        expect(store.load_secret('second').to_h).to eql example_secret_2.to_h
      end

      it 'accepts an empty export' do
        yaml_file = Tempfile.new('empty_secret_store.yml')
        yaml_file.write(YAML.dump({}))
        yaml_file.close

        store = described_class.import_yaml(yaml_file.path, ':memory:')

        expect(store.load_password).to be_nil
        expect(store.all_secrets).to be_empty
      ensure
        yaml_file&.unlink
      end
    end
  end

  describe 'instance methods' do
    subject { described_class.new(':memory:') }

    def db_num_secrets
      subject.db.execute('SELECT count(*) FROM secret').first.first
    end

    def db_num_passwords
      subject.db.execute('SELECT count(*) FROM master_password').first.first
    end

    describe '#save_password' do
      it 'writes password data to database' do
        expect(db_num_passwords).to be 0
        subject.save_password example_password
        expect(db_num_passwords).to be 1
      end

      it 'is idempotent' do
        expect(db_num_passwords).to be 0
        5.times { subject.save_password example_password }
        expect(db_num_passwords).to be 1
      end
    end

    describe '#load_password' do
      it 'returns nil when there is no password' do
        expect(subject.load_password).to be_nil
      end

      it 'returns password data when there is one' do
        subject.save_password example_password
        pw_from_store = subject.load_password
        expect(pw_from_store.to_h).to eql example_password.to_h
      end
    end

    describe '#save_secret' do
      it 'adds new secret to database' do
        expect(db_num_secrets).to be 0
        subject.save_secret(example_secret_1)
        expect(db_num_secrets).to be 1
      end

      it 'is idempotent' do
        expect(db_num_secrets).to be 0
        5.times { subject.save_secret(example_secret_1) }
        expect(db_num_secrets).to be 1
      end

      it 'adds new serets indexed by the label' do
        expect(db_num_secrets).to be 0
        subject.save_secret(example_secret_1)
        expect(db_num_secrets).to be 1
        subject.save_secret(example_secret_2)
        expect(db_num_secrets).to be 2
      end
    end

    describe '#load_secret' do
      it 'returns nil when there is no secret with matching label' do
        expect(subject.load_secret('example')).to be_nil
        subject.save_secret(example_secret_1)
        expect(subject.load_secret('anything_else')).to be_nil
      end

      it 'returns a new valid secret when extracted by label' do
        subject.save_secret(example_secret_1)
        subject.save_secret(example_secret_2)

        first_secret = subject.load_secret('example')
        expect(first_secret).to be_a SecretStore::Secret
        expect(first_secret.decrypt_text(example_checksum)).to eql example_plaintext_1

        second_secret = subject.load_secret('second')
        expect(second_secret).to be_a SecretStore::Secret
        expect(second_secret.decrypt_text(example_checksum)).to eql example_plaintext_2
      end
    end

    describe '#delete_secret' do
      before do
        subject.save_secret(example_secret_1)
        subject.save_secret(example_secret_2)
      end

      it 'makes no difference when there is no matching label' do
        subject.delete_secret('qwerty')

        expect(db_num_secrets).to be 2

        first_secret = subject.load_secret('example')
        expect(first_secret).to be_a SecretStore::Secret
        expect(first_secret.decrypt_text(example_checksum)).to eql example_plaintext_1

        second_secret = subject.load_secret('second')
        expect(second_secret).to be_a SecretStore::Secret
        expect(second_secret.decrypt_text(example_checksum)).to eql example_plaintext_2
      end

      it 'removes an existing secret without affecting others' do
        subject.delete_secret('example')

        expect(db_num_secrets).to be 1

        first_secret = subject.load_secret('example')
        expect(first_secret).to be_nil

        second_secret = subject.load_secret('second')
        expect(second_secret).to be_a SecretStore::Secret
        expect(second_secret.decrypt_text(example_checksum)).to eql example_plaintext_2
      end
    end

    describe '#export_yaml' do
      before do
        @yaml_file = Tempfile.new('secret_store_test.yml').path
        @store = described_class.new(File.join(File.dirname(__FILE__), 'fixture_store.dat'))
        FileUtils.rm_f @yaml_file
      end

      it 'writes a file' do
        @store.export_yaml(@yaml_file)
        expect(File.size?(@yaml_file)).to be > 200
      end

      it 'saves YAML data to the file' do
        @store.export_yaml(@yaml_file)
        exported_data = YAML.safe_load_file(@yaml_file, permitted_classes: [Symbol])
        expect(exported_data).to eql({ master_password: { bcrypt_salt: '$2a$14$.WO3JtKxNhzlASL4eQpkEO',
                                                          pbkdf2_salt: 'rCLPwKKsFb5WwgY1y0LwAQ==',
                                                          test_encryption: example_cipher },
                                       secrets: [
                                         { label: 'example',
                                           iv: 'u0CAnSPnSbN1sVi03_ck4A==',
                                           crypted_text: 'IWYGh4x98_4Flk_1OrhvaaI=',
                                           auth_tag: 'szbH9SG0pymGCpU3lkIWNA==',
                                           pbkdf2_salt: 'yLIp8f6eeIzxOEvA1-uzbw==' }
                                       ] })
      end
    end

    describe '#all_secrets' do
      it 'returns empty array when there are no secrets in the store' do
        expect(subject.all_secrets).to be_empty
      end

      it 'returns array of all secrets in the store' do
        subject.save_secret(example_secret_1)
        subject.save_secret(example_secret_2)

        got_secrets = subject.all_secrets
        expect(got_secrets.count).to be 2

        expected_plaintexts = [example_plaintext_1, example_plaintext_2]
        got_secrets.sort_by(&:label).zip(expected_plaintexts).each do |secret, plaintext|
          expect(secret).to be_a SecretStore::Secret
          expect(secret.decrypt_text(example_checksum)).to eql plaintext
        end
      end
    end
  end
end
