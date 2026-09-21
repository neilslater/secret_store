# frozen_string_literal: true

module SecretStore
  # Invalid encrypted record structure. Messages name fields, never supplied values.
  class FormatError < RuntimeError; end

  # Shared structural validation for SQLite, YAML, and directly constructed records.
  # Valid structure does not establish authenticity; that requires decryption with a key.
  module RecordValidation
    private

    def validate_fields(attributes, fields)
      raise FormatError, 'record must be a Hash' unless attributes.is_a?(Hash)

      fields.each do |field|
        raise FormatError, "Missing hash key #{field}" unless attributes.key?(field)
      end
    end

    def validate_string(value, field)
      raise FormatError, "#{field} must be a String" unless value.is_a?(String)
    end

    def validate_bytes(value, field, length = nil)
      validate_string(value, field)
      begin
        raise ArgumentError unless value.match?(/\A[A-Za-z0-9_-]*={0,2}\z/)

        bytes = Base64.urlsafe_decode64(value)
      rescue ArgumentError
        raise FormatError, "#{field} must be URL-safe Base64"
      end
      raise FormatError, "#{field} must contain #{length} bytes" if length && bytes.bytesize != length

      bytes
    end

    def validate_iv(value)
      # Preserve the public boundary: OpenSSL historically used the first 12 bytes.
      raise FormatError, 'iv must contain at least 12 bytes' if validate_bytes(value, :iv).bytesize < 12
    end

    def validate_secret(label, initial_vector, salt, ciphertext, tag)
      validate_string(label, :label)
      validate_iv(initial_vector)
      validate_bytes(salt, :pbkdf2_salt, 16)
      validate_bytes(ciphertext, :crypted_text)
      validate_bytes(tag, :auth_tag, 16)
    end

    def validate_password(salt, pbkdf2_salt, test_encryption)
      validate_string(salt, :bcrypt_salt)
      unless BCrypt::Engine.valid_salt?(salt) && salt.length == 29
        raise FormatError, 'Bad bcrypt_salt: expected a BCrypt salt'
      end

      validate_bytes(pbkdf2_salt, :pbkdf2_salt, 16)
      validate_test_encryption(test_encryption)
    end

    def validate_test_encryption(value)
      validate_string(value, :test_encryption)
      parts = value.split(' ~ ', -1)
      raise FormatError, 'test_encryption must contain exactly three parts' unless parts.length == 3

      validate_iv(parts[0])
      validate_bytes(parts[1], :crypted_text)
      validate_bytes(parts[2], :auth_tag, 16)
      parts
    end
  end
end
