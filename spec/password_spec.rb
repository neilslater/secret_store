# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Password do
  let(:example_password) { 'QwertyUiop' }
  let(:example_bcrypt_salt) { '$2a$14$.WO3JtKxNhzlASL4eQpkEO' }
  let(:example_pbkdf_salt) { 'rCLPwKKsFb5WwgY1y0LwAQ==' }
  let(:example_cipher) do
    '9_ZGG1_mabi9Q5qvxu4sOA== ~ k4TSdX28eTImvdDmzhtju-87-35msJBPilU_25JG6UE= ~ dKxORrEkMFsW_uAsr3fGHA=='
  end
  let(:example_checksum) { '3EG3i1.oq1T5cmZVlq.cnOt28gz6U8G' }

  describe 'class methods' do
    describe '#new' do
      it 'creates valid object from good password hash' do
        expect(SecretStore::Password.new(example_bcrypt_salt, example_pbkdf_salt,
                                         example_cipher)).to be_a SecretStore::Password
      end

      it 'does not create a Password object from Strings which are not bcrypt salts' do
        bad_pw_hashes = ['', 'hello', 'Secret', 'nil', example_bcrypt_salt + example_checksum]
        bad_pw_hashes.each do |bad_pw_hash|
          expect do
            SecretStore::Password.new(bad_pw_hash, example_pbkdf_salt, example_cipher)
          end.to raise_error RuntimeError, /Bad bcrypt_salt/
        end
      end
    end

    describe '#create' do
      it 'creates new object' do
        expect(SecretStore::Password.create('super-secret')).to be_a SecretStore::Password
      end

      it 'matches to original password' do
        pw = SecretStore::Password.create('super-secret')
        expect(pw.activate_checksum('super-secret')).to be_truthy
      end
    end

    describe '#from_h' do
      it 'creates valid object from serialisation' do
        h = { bcrypt_salt: example_bcrypt_salt, pbkdf2_salt: example_pbkdf_salt,
              test_encryption: example_cipher }
        expect(SecretStore::Password.from_h(h)).to be_a SecretStore::Password
      end
    end
  end

  describe 'instance methods' do
    subject { SecretStore::Password.new(example_bcrypt_salt, example_pbkdf_salt, example_cipher) }

    describe '#activate_checksum' do
      it 'generates correct checksum value' do
        expect(subject.activate_checksum(example_password)).to eql example_checksum
      end

      it 'sets checksum property' do
        subject.activate_checksum(example_password)
        expect(subject.checksum).to eql example_checksum
      end

      it 'raises error for incorrect passwords' do
        bad_pws = [nil, '', 'password', example_checksum, example_bcrypt_salt, example_pbkdf_salt]
        bad_pws.each do |bad_pw|
          expect do
            subject.activate_checksum(bad_pw)
          end.to raise_error RuntimeError, /password/
        end
      end
    end

    describe '#to_h' do
      it 'returns a Hash' do
        expect(subject.to_h).to be_a Hash
      end

      it 'can be passed into SecretStore::Password.from_h to re-create same password' do
        serialised = subject.to_h
        deserialised = SecretStore::Password.from_h(serialised)
        expect(deserialised.activate_checksum(example_password)).to eql example_checksum
      end
    end
  end
end
