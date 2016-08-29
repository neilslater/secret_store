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

  class Secret
    include CoreMethods
    extend CoreMethods

    attr_reader :label, :iv, :crypted_text, :pbkdf2_salt

    def initialize label, iv_b64, pbkdf2_salt_b64, crypted_text_b64
      @label = label.to_s
      @iv = iv_b64
      @pbkdf2_salt = pbkdf2_salt_b64
      @crypted_text = crypted_text_b64
    end

    def self.create_from_plaintext label, new_text, password
      iv_b64 = encode_bytes( SecureRandom.random_bytes(16) )
      pbkdf2_salt_b64 = encode_bytes( SecureRandom.random_bytes(16) )
      key = key_from_password( password, decode_bytes(pbkdf2_salt_b64) )
      crypted_text_b64 = encode_bytes( encrypt_string( new_text, key, decode_bytes( iv_b64 ) ) )
      self.new( label, iv_b64, pbkdf2_salt_b64, crypted_text_b64 )
    end

    def decrypt_text password
      key = key_from_password( password, decode_bytes(pbkdf2_salt) )
      decrypt_string decode_bytes( crypted_text ), key, decode_bytes( iv )
    end

    def replace_text new_plaintext, password
      @iv = encode_bytes( SecureRandom.random_bytes(16) )
      @pbkdf2_salt = encode_bytes( SecureRandom.random_bytes(16) )
      key = key_from_password( password, decode_bytes(pbkdf2_salt) )
      @crypted_text = encode_bytes( encrypt_string( new_plaintext, key, decode_bytes( iv ) ) )
    end

    def to_h
      Hash[
        :label => @label,
        :iv => @iv,
        :pbkdf2_salt => @pbkdf2_salt,
        :crypted_text => @crypted_text
      ]
    end

    def self.from_h h
      [:label, :iv, :pbkdf2_salt, :crypted_text].each do |property|
        unless h.has_key? property
          raise "Missing hash key #{property}"
        end
      end

      self.new( h[:label], h[:iv], h[:pbkdf2_salt], h[:crypted_text] )
    end
  end
end
