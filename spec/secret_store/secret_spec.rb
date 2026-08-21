# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::Secret do
  describe 'class methods' do
    describe '#new' do
      it 'creates valid, decryptable object' do
        secret = described_class.new(secret_label, secret_iv, secret_pbkdf2_salt, secret_crypted_text,
                                     secret_auth_tag)
        expect(secret.decrypt_text(example_checksum)).to eql primary_plaintext
      end
    end

    describe '#from_h' do
      it 'creates valid, decryptable object from hash-based serialisation' do
        secret = described_class.from_h(serialized_secret_attributes)
        expect(secret.decrypt_text(example_checksum)).to eql primary_plaintext
      end

      it 'rejects serialisations missing required fields' do
        %i[label iv crypted_text].each do |property|
          expect { described_class.from_h(serialized_secret_attributes.except(property)) }
            .to raise_error RuntimeError, /Missing hash key #{property}/
        end
      end
    end

    describe '#create_from_plaintext' do
      it 'creates a valid, decryptable object' do
        secret = described_class.create_from_plaintext(secret_label, primary_plaintext, example_checksum)
        expect(secret.decrypt_text(example_checksum)).to eql primary_plaintext
      end

      it 'uses a different initial value each time' do
        initial_values = [*0..10].map do
          secret = described_class.create_from_plaintext(secret_label, primary_plaintext, example_checksum)
          secret.iv
        end
        expect(initial_values.uniq).to eql initial_values
      end

      it 'uses a different pbkdf2 salt value each time' do
        salts = [*0..10].map do
          secret = described_class.create_from_plaintext(secret_label, primary_plaintext, example_checksum)
          secret.pbkdf2_salt
        end
        expect(salts.uniq).to eql salts
      end

      it 'has a different crypted text each time' do
        encrypted_texts = [*0..10].map do
          secret = described_class.create_from_plaintext(secret_label, primary_plaintext, example_checksum)
          secret.crypted_text
        end
        expect(encrypted_texts.uniq).to eql encrypted_texts
      end
    end
  end

  describe 'instance methods' do
    subject(:encrypted_secret) { described_class.from_h(serialized_secret_attributes) }

    describe '#decrypt_text' do
      it 'works when the key is correct' do
        expect(encrypted_secret.decrypt_text(example_checksum)).to eql primary_plaintext
      end

      it 'raises error when the key is incorrect' do
        ['', 'wrong', SecureRandom.random_bytes(32)].each do |invalid_checksum|
          expect { encrypted_secret.decrypt_text(invalid_checksum) }
            .to raise_error OpenSSL::Cipher::CipherError
        end
      end

      it 'does not change the encrypted attributes', :aggregate_failures do
        plaintext = encrypted_secret.decrypt_text(example_checksum)
        expect(plaintext).to eql primary_plaintext
        expect(encrypted_secret.to_h).to eql serialized_secret_attributes
      end

      it 'raises error when crypted text has been tampered with' do
        tampered_secret = secret_with_cipher(flip_last_cipher_bit(secret_crypted_text))
        expect { tampered_secret.decrypt_text(example_checksum) }
          .to raise_error OpenSSL::Cipher::CipherError
      end

      it 'decrypts after the tampering operation is reversed' do
        restored_cipher = flip_last_cipher_bit(flip_last_cipher_bit(secret_crypted_text))
        expect(secret_with_cipher(restored_cipher).decrypt_text(example_checksum)).to eql primary_plaintext
      end

      it 'raises error when label is changed' do
        tampered_secret = described_class.new('new_label', secret_iv, secret_pbkdf2_salt, secret_crypted_text,
                                              secret_auth_tag)
        expect { tampered_secret.decrypt_text(example_checksum) }
          .to raise_error OpenSSL::Cipher::CipherError
      end
    end

    describe '#replace_text' do
      it 'works using same checksum' do
        new_message = 'Another different secret!'
        encrypted_secret.replace_text(new_message, example_checksum)
        expect(encrypted_secret.decrypt_text(example_checksum)).to eql new_message
      end

      it 'works using a new checksum' do
        new_message = 'Another different secret!'
        new_checksum = SecureRandom.random_bytes(32)
        encrypted_secret.replace_text(new_message, new_checksum)
        expect(encrypted_secret.decrypt_text(new_checksum)).to eql new_message
      end

      it 'changes every encryption value even if key and message are the same', :aggregate_failures do
        encrypted_secret.replace_text(primary_plaintext, example_checksum)
        expect(encrypted_secret.decrypt_text(example_checksum)).to eql primary_plaintext
        expect(changed_encryption_values(encrypted_secret)).to all(satisfy { |current, original| current != original })
      end
    end

    describe '#to_h' do
      it 'serialises the object', :aggregate_failures do
        restored_secret = described_class.from_h(encrypted_secret.to_h)
        expect(restored_secret.decrypt_text(example_checksum)).to eql primary_plaintext
        expect(restored_secret.to_h).to eql serialized_secret_attributes
      end
    end
  end
end
