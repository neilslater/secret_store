# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Password do
  describe 'class methods' do
    describe '#new' do
      it 'creates valid object from good password hash' do
        expect(described_class.new(example_bcrypt_salt, example_pbkdf_salt,
                                   example_cipher)).to be_a described_class
      end

      it 'does not create a Password object from Strings which are not bcrypt salts' do
        invalid_salts = ['', 'hello', 'Secret', 'nil', example_bcrypt_salt + example_checksum]
        invalid_salts.each do |invalid_salt|
          expect { described_class.new(invalid_salt, example_pbkdf_salt, example_cipher) }
            .to raise_error RuntimeError, /Bad bcrypt_salt/
        end
      end

      it 'rejects PBKDF salts which are not 16 bytes' do
        expect do
          described_class.new(example_bcrypt_salt, Base64.urlsafe_encode64('short'), example_cipher)
        end.to raise_error RuntimeError, /Unexpected size/
      end
    end

    describe '#create' do
      it 'creates new object' do
        expect(described_class.create('super-secret')).to be_a described_class
      end

      it 'matches to original password' do
        password_record = described_class.create('super-secret')
        expect(password_record.activate_checksum('super-secret')).to be_truthy
      end
    end

    describe '#from_h' do
      it 'creates valid object from serialisation' do
        attributes = { bcrypt_salt: example_bcrypt_salt, pbkdf2_salt: example_pbkdf_salt,
                       test_encryption: example_cipher }
        expect(described_class.from_h(attributes)).to be_a described_class
      end
    end
  end

  describe 'instance methods' do
    subject(:password_record) { described_class.new(example_bcrypt_salt, example_pbkdf_salt, example_cipher) }

    describe '#activate_checksum' do
      it 'generates correct checksum value' do
        expect(password_record.activate_checksum(example_password)).to eql example_checksum
      end

      it 'sets checksum property' do
        password_record.activate_checksum(example_password)
        expect(password_record.checksum).to eql example_checksum
      end

      it 'raises error for incorrect passwords' do
        invalid_passwords = [nil, '', 'password', example_checksum, example_bcrypt_salt, example_pbkdf_salt]
        invalid_passwords.each do |invalid_password|
          expect { password_record.activate_checksum(invalid_password) }
            .to raise_error RuntimeError, /password/
        end
      end
    end

    describe '#to_h' do
      it 'returns a Hash' do
        expect(password_record.to_h).to be_a Hash
      end

      it 'can be passed into SecretStore::Password.from_h to re-create same password' do
        serialised = password_record.to_h
        deserialised = described_class.from_h(serialised)
        expect(deserialised.activate_checksum(example_password)).to eql example_checksum
      end
    end
  end
end
