# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Secret do
  let(:example_checksum) { '3EG3i1.oq1T5cmZVlq.cnOt28gz6U8G' }
  let(:example_label) { 'example' }
  let(:example_iv) { 'T21EPfxrJbLHJQvkB6mLXQ==' }
  let(:example_pbkdf2_salt) { 'fyKRMBY6hPpqXzj_XOjvQw==' }
  let(:example_crypted_text) { 'kDKTjtTYyvkLIGa2teBYzgc=' }
  let(:example_auth_tag) { 'upzYf6VkGXMuS9ccAhTFPg==' }

  let(:example_plaintext) { 'This is a secret!' }

  describe 'class methods' do
    describe '#new' do
      it 'creates valid, decryptable object' do
        secret = SecretStore::Secret.new(example_label, example_iv, example_pbkdf2_salt, example_crypted_text,
                                         example_auth_tag)
        expect(secret.decrypt_text(example_checksum)).to eql example_plaintext
      end
    end

    describe '#from_h' do
      it 'creates valid, decryptable object from hash-based serialisation' do
        h = { label: example_label,
              iv: example_iv,
              pbkdf2_salt: example_pbkdf2_salt,
              crypted_text: example_crypted_text,
              auth_tag: example_auth_tag }
        secret = SecretStore::Secret.from_h(h)
        expect(secret.decrypt_text(example_checksum)).to eql example_plaintext
      end
    end

    describe '#create_from_plaintext' do
      it 'creates a valid, decryptable object' do
        secret = SecretStore::Secret.create_from_plaintext(example_label, example_plaintext, example_checksum)
        expect(secret.decrypt_text(example_checksum)).to eql example_plaintext
      end

      it 'uses a different initial value each time' do
        ivs = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext(example_label, example_plaintext, example_checksum)
          secret.iv
        end
        expect(ivs.uniq).to eql ivs
      end

      it 'uses a different pbkdf2 salt value each time' do
        salts = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext(example_label, example_plaintext, example_checksum)
          secret.pbkdf2_salt
        end
        expect(salts.uniq).to eql salts
      end

      it 'has a different crypted text each time' do
        crypted_texts = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext(example_label, example_plaintext, example_checksum)
          secret.crypted_text
        end
        expect(crypted_texts.uniq).to eql crypted_texts
      end
    end
  end

  describe 'instance methods' do
    subject do
      SecretStore::Secret.new(example_label, example_iv, example_pbkdf2_salt, example_crypted_text, example_auth_tag)
    end

    describe '#decrypt_text' do
      it 'works when the key is correct' do
        expect(subject.decrypt_text(example_checksum)).to eql example_plaintext
      end

      it 'raises error when the key is incorrect' do
        bad_checksums = ['', 'wrong', SecureRandom.random_bytes(32)]
        bad_checksums.each do |bad_checksum|
          expect do
            subject.decrypt_text(bad_checksum)
          end.to raise_error OpenSSL::Cipher::CipherError
        end
      end

      it 'does not change iv, pbkdf2_salt, crypted text or auth_tag' do
        expect(subject.decrypt_text(example_checksum)).to eql example_plaintext

        expect(subject.iv).to eql example_iv
        expect(subject.pbkdf2_salt).to eql example_pbkdf2_salt
        expect(subject.crypted_text).to eql example_crypted_text
        expect(subject.auth_tag).to eql example_auth_tag
      end

      it 'raises error when crypted text has been tampered with' do
        copy_cipher = Base64.urlsafe_decode64(subject.crypted_text)
        copy_cipher[-1] = (copy_cipher[-1].ord ^ 4).chr # xor a bit on last chaacter
        tampered_secret = SecretStore::Secret.new(example_label, example_iv, example_pbkdf2_salt,
                                                  Base64.urlsafe_encode64(copy_cipher), example_auth_tag)
        expect do
          tampered_secret.decrypt_text(example_checksum)
        end.to raise_error OpenSSL::Cipher::CipherError

        # Just to confirm the code above would otherwise the valid if we undo the tampering
        copy_cipher[-1] = (copy_cipher[-1].ord ^ 4).chr # xor a bit on last chaacter
        fixed_secret = SecretStore::Secret.new(example_label, example_iv, example_pbkdf2_salt,
                                               Base64.urlsafe_encode64(copy_cipher), example_auth_tag)
        expect(fixed_secret.decrypt_text(example_checksum)).to eql example_plaintext
      end

      it 'raises error when label is changed' do
        tampered_secret = SecretStore::Secret.new('new_label', example_iv, example_pbkdf2_salt,
                                                  example_crypted_text, example_auth_tag)
        expect do
          tampered_secret.decrypt_text(example_checksum)
        end.to raise_error OpenSSL::Cipher::CipherError
      end
    end

    describe '#replace_text' do
      it 'works using same checksum' do
        new_message = 'Another different secret!'
        subject.replace_text(new_message, example_checksum)
        expect(subject.decrypt_text(example_checksum)).to eql new_message
      end

      it 'works using a new checksum' do
        new_message = 'Another different secret!'
        new_checksum = SecureRandom.random_bytes(32)
        subject.replace_text(new_message, new_checksum)
        expect(subject.decrypt_text(new_checksum)).to eql new_message
      end

      it 'changes iv, pbkdf2_salt, crypted text and auth_tag even if key and message are the same' do
        subject.replace_text(example_plaintext, example_checksum)
        expect(subject.decrypt_text(example_checksum)).to eql example_plaintext

        expect(subject.iv).to_not eql example_iv
        expect(subject.crypted_text).to_not eql example_crypted_text
        expect(subject.pbkdf2_salt).to_not eql example_pbkdf2_salt
        expect(subject.auth_tag).to_not eql example_auth_tag
      end
    end

    describe '#to_h' do
      it 'serialises the object' do
        h = subject.to_h
        secret = SecretStore::Secret.from_h(h)
        expect(secret.decrypt_text(example_checksum)).to eql example_plaintext
        expect(subject.label).to eql example_label
        expect(subject.iv).to eql example_iv
        expect(subject.pbkdf2_salt).to eql example_pbkdf2_salt
        expect(subject.crypted_text).to eql example_crypted_text
        expect(subject.auth_tag).to eql example_auth_tag
      end
    end
  end
end
