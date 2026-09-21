# frozen_string_literal: true

require 'spec_helper'

describe SecretStore::RecordValidation do
  describe 'secret records' do
    [nil, 42, [], 'record'].each do |value|
      it "rejects a #{value.class} envelope" do
        expect { SecretStore::Secret.from_h(value) }.to raise_error(SecretStore::FormatError, /Hash/)
      end
    end

    %i[label iv pbkdf2_salt crypted_text auth_tag].each do |field|
      [nil, 42].each do |value|
        it "rejects #{value.class} in #{field}" do
          expect { SecretStore::Secret.from_h(serialized_secret_attributes.merge(field => value)) }
            .to raise_error(SecretStore::FormatError, /#{field}/)
        end
      end
    end

    %i[iv pbkdf2_salt crypted_text auth_tag].each do |field|
      it "rejects malformed Base64 in #{field}" do
        expect { SecretStore::Secret.from_h(serialized_secret_attributes.merge(field => '%private%')) }
          .to raise_error(SecretStore::FormatError, /#{field} must be URL-safe Base64/)
      end
    end

    ['a', 'a===', '+/=='].each do |value|
      it 'rejects invalid Base64 padding or alphabet' do
        expect { SecretStore::Secret.from_h(serialized_secret_attributes.merge(crypted_text: value)) }
          .to raise_error(SecretStore::FormatError, /crypted_text/)
      end
    end

    [0, 15, 17].each do |length|
      it "rejects a #{length}-byte secret salt" do
        attributes = serialized_secret_attributes.merge(pbkdf2_salt: Base64.urlsafe_encode64('s' * length))
        expect { SecretStore::Secret.from_h(attributes) }.to raise_error(SecretStore::FormatError, /pbkdf2_salt/)
      end
    end

    [0, 11].each do |length|
      it "rejects a #{length}-byte IV" do
        attributes = serialized_secret_attributes.merge(iv: Base64.urlsafe_encode64('i' * length))
        expect { SecretStore::Secret.from_h(attributes) }.to raise_error(SecretStore::FormatError, /iv/)
      end
    end

    [12, 16, 20].each do |length|
      it "retains the first 12 bytes of a #{length}-byte IV" do
        raw_iv = Base64.urlsafe_decode64(secret_iv)[0, 12].ljust(length, 'i')
        attributes = serialized_secret_attributes.merge(iv: Base64.urlsafe_encode64(raw_iv))
        expect(SecretStore::Secret.from_h(attributes).decrypt_text(example_checksum)).to eq(primary_plaintext)
      end
    end

    ['', "\x00\xff\x80".b, '秘密'].each do |plaintext|
      it "round-trips #{plaintext.bytesize} bytes with a non-ASCII label" do
        secret = SecretStore::Secret.create_from_plaintext('秘密', plaintext, example_checksum)
        expect(secret.decrypt_text(example_checksum).b).to eq(plaintext.b)
      end
    end
  end

  describe 'authentication tags' do
    [*0..15, 17, 32].each do |length|
      it "rejects a #{length}-byte secret tag at construction and after mutation", :aggregate_failures do
        attributes = serialized_secret_attributes.merge(auth_tag: Base64.urlsafe_encode64('t' * length))
        expect { SecretStore::Secret.from_h(attributes) }.to raise_error(SecretStore::FormatError, /auth_tag/)
        secret = SecretStore::Secret.from_h(serialized_secret_attributes.transform_values(&:dup))
        secret.auth_tag.replace(attributes[:auth_tag])
        expect { secret.decrypt_text(example_checksum) }.to raise_error(SecretStore::FormatError, /auth_tag/)
      end

      it "rejects a #{length}-byte password tag before authentication" do
        parts = example_cipher.split(' ~ ')
        parts[2] = Base64.urlsafe_encode64('t' * length)
        expect { SecretStore::Password.new(example_bcrypt_salt, example_pbkdf_salt, parts.join(' ~ ')) }
          .to raise_error(SecretStore::FormatError, /auth_tag/)
      end
    end

    %i[iv auth_tag].each do |field|
      it "rejects tampering with a full-length #{field}" do
        bytes = Base64.urlsafe_decode64(serialized_secret_attributes[field])
        bytes.setbyte(0, bytes.getbyte(0) ^ 1)
        attributes = serialized_secret_attributes.merge(field => Base64.urlsafe_encode64(bytes))
        expect { SecretStore::Secret.from_h(attributes).decrypt_text(example_checksum) }
          .to raise_error(OpenSSL::Cipher::CipherError)
      end
    end

    it 'checks the shared decryption boundary for non-String tags' do
      expect { primary_secret.decrypt_string('', nil, '', '') }.to raise_error(SecretStore::FormatError, /auth_tag/)
    end
  end

  describe 'password records' do
    [nil, 12, '', 'a ~ b', 'a ~ b ~ c ~ d'].each do |value|
      it "rejects malformed verification material (#{value.class})" do
        expect { SecretStore::Password.new(example_bcrypt_salt, example_pbkdf_salt, value) }
          .to raise_error(SecretStore::FormatError, /test_encryption/)
      end
    end

    it 'checks every required password field' do
      fixture_password.to_h.each_key do |field|
        expect { SecretStore::Password.from_h(fixture_password.to_h.except(field)) }
          .to raise_error(SecretStore::FormatError, /#{field}/)
      end
    end

    it 'rejects a non-String BCrypt salt without printing its value' do
      expect { SecretStore::Password.new(nil, example_pbkdf_salt, example_cipher) }
        .to raise_error(SecretStore::FormatError, 'bcrypt_salt must be a String')
    end

    it 'revalidates mutable verification material during activation' do
      password = SecretStore::Password.new(example_bcrypt_salt, example_pbkdf_salt, example_cipher.dup)
      password.test_encryption.replace(example_cipher.split(' ~ ')[0, 2].join(' ~ '))
      expect { password.activate_checksum(example_password) }.to raise_error(SecretStore::FormatError)
    end
  end

  describe 'failed replacement' do
    subject(:secret) { primary_secret }

    let!(:original) { secret.to_h.dup }

    it 'preserves the record after invalid plaintext', :aggregate_failures do
      expect { secret.replace_text(nil, example_checksum) }.to raise_error(TypeError)
      expect(secret.to_h).to eq(original)
      expect(secret.decrypt_text(example_checksum)).to eq(primary_plaintext)
    end

    %i[random_pbkdf2_salt key_from_checksum encrypt_string].each do |operation|
      it "preserves the record after #{operation} fails", :aggregate_failures do
        allow(SecretStore::Secret).to receive(operation).and_raise(RuntimeError, 'injected failure')
        expect { secret.replace_text('replacement', example_checksum) }.to raise_error('injected failure')
        expect(secret.to_h).to eq(original)
        expect(secret.decrypt_text(example_checksum)).to eq(primary_plaintext)
      end
    end

    it 'preserves the record after RNG failure', :aggregate_failures do
      allow(SecureRandom).to receive(:random_bytes).and_raise(RuntimeError, 'RNG failure')
      expect { secret.replace_text('replacement', example_checksum) }.to raise_error('RNG failure')
      expect(secret.to_h).to eq(original)
      expect(secret.decrypt_text(example_checksum)).to eq(primary_plaintext)
    end
  end
end
