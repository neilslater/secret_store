require 'openssl'
require 'securerandom'
require 'base64'

module SecretStore
  # This module contains the logic for all encoding and encrypting performed by the rest of the
  # project. Internally, encryption is provided by OpenSSL. There are no cryptography algorithms implemented
  # here (or elsewhere in SecretStore)
  #
  module CoreMethods
    # Cipher type selected from possible choices in OpenSSL. Note that the rest of the code here
    # assumes an authenticated encryption method, so we're pretty much limited to aes-128-gcm and
    # aes-256-gcm without further changes.
    CIPHER_TYPE = 'aes-256-gcm'

    # Key length in bytes of key used by chosen cipher
    KEY_LENGTH = 32

    # Number of iterations to use when deriving a key from password
    PBKDF_ITERATIONS = 100000

    # Convert String of arbitrary bytes to String suitable for storing. Inverse of decode_bytes.
    # @param [String] raw_bytes bytes to encode
    # @return [String] encoded bytes
    #
    def encode_bytes raw_bytes
      Base64.urlsafe_encode64( raw_bytes )
    end

    # Convert String from storage to original String of bytes. Inverse of encode_bytes.
    # @param [String] encoded_bytes string from storage
    # @return [String] original bytes
    #
    def decode_bytes encoded_bytes
      Base64.urlsafe_decode64( encoded_bytes )
    end

    # Create encrypted version of input String.
    # @param [String] plaintext message to encrypt
    # @param [String] key secret key used by cipher
    # @param [String] iv initial value (non-secret, but important to use unique initial values to avoid giving away parts of messages)
    # @param [String] auth_data authentication data which must be same for encrypt and decrypt
    # @return [Array<String>] encrypted text and auth_tag values
    #
    def encrypt_string plaintext, key, iv, auth_data = ''
      cipher = OpenSSL::Cipher.new( CIPHER_TYPE )
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_data = auth_data

      encrypted = cipher.update( plaintext ) + cipher.final
      [encrypted, cipher.auth_tag]
    end

    # Create encrypted version of input String.
    # @param [String] ciphertext encrypted message
    # @param [String] auth_tag authentication data (for detecting tampering)
    # @param [String] key secret key used by cipher, must be same as used to create ciphertext
    # @param [String] iv initial value, must be same as used to create ciphertext
    # @param [String] auth_data authentication data which must be same for encrypt and decrypt
    # @return [String] plaintext decrypted from the ciphertext
    #
    def decrypt_string ciphertext, auth_tag, key, iv, auth_data = ''
      cipher = OpenSSL::Cipher.new( CIPHER_TYPE )
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = auth_tag
      cipher.auth_data = auth_data

      cipher.update( ciphertext ) + cipher.final
    end

    # Derive key for cipher from a text password
    # @param [String] password secret text phrase used in generator
    # @param [String] salt typically random, but non-secret, value used to ensure variation between uses of the derivation function
    # @return [String] key suitable for use in chosen cipher
    #
    def key_from_password password, salt
      OpenSSL::PKCS5.pbkdf2_hmac( password, salt,
                                  PBKDF_ITERATIONS, KEY_LENGTH,
                                  OpenSSL::Digest::SHA256.new )
    end
  end
end
