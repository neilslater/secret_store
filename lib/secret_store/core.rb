require 'openssl'
require 'securerandom'
require 'base64'

module SecretStore
  module CoreMethods
    CIPHER_TYPE = 'aes-256-cbc'
    KEY_LENGTH = 32
    PBKDF_ITERATIONS = 100000

    def encode_bytes raw_bytes
      Base64.urlsafe_encode64( raw_bytes )
    end

    def decode_bytes encoded_bytes
      Base64.urlsafe_decode64( encoded_bytes )
    end

    def encrypt_string plaintext, key, iv
      cipher = OpenSSL::Cipher.new( CIPHER_TYPE )
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv

      cipher.update( plaintext ) + cipher.final
    end

    def decrypt_string ciphertext, key, iv
      cipher = OpenSSL::Cipher.new( CIPHER_TYPE )
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv

      cipher.update( ciphertext ) + cipher.final
    end

    def key_from_password password, salt
      OpenSSL::PKCS5.pbkdf2_hmac( password, salt,
                                  PBKDF_ITERATIONS, KEY_LENGTH,
                                  OpenSSL::Digest::SHA256.new )
    end
  end
end
