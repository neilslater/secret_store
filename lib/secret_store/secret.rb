require 'openssl'
require 'securerandom'
require 'base64'

module SecretStore
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
