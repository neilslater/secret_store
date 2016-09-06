require 'openssl'
require 'securerandom'
require 'base64'

module SecretStore
  # This class models encrypted messages. The encryption is provided via SecretStore::CoreMethods,
  # and ultimately from OpenSSL.
  #
  # An instance of this class represents a single identified encrypted message, plus a public initial
  # value used randomise first block to be encrypted (which allows safe key re-use).
  #
  class Secret
    include CoreMethods
    extend CoreMethods

    # Identifier for the secret, should be unique within a store.
    # @return [String]
    attr_reader :label

    # Initial value for encryption, base64 encoded (URL safe variant).
    # @return [String]
    attr_reader :iv

    # Encrypted message, base64 encoded (URL safe variant).
    # @return [String]
    attr_reader :crypted_text

    # Constructs valid secret from strings as they are stored in SecretStore.
    # @param [String] label identifier for the secret, should be unique within a store
    # @param [String] iv_b64 initial value for encryption, base64 encoded (URL safe variant)
    # @param [String] crypted_text_b64 encrypted message, base64 encoded (URL safe variant)
    # @return [SecretStore::Secret] new object
    def initialize label, iv_b64, crypted_text_b64
      @label = label.to_s
      @iv = iv_b64
      @crypted_text = crypted_text_b64
    end

    # Constructs valid secret from plaintext, encrypting it using supplied password. The
    # initial value for encryption is generated automatically using SecureRandom.
    # @param [String] label identifier for the secret, should be unique within a store
    # @param [String] new_text plaintext version of message
    # @param [String] key encryption key
    # @return [SecretStore::Secret] new object
    def self.create_from_plaintext label, new_text, key
      iv_b64 = encode_bytes( SecureRandom.random_bytes(16) )
      crypted_text_b64 = encode_bytes( encrypt_string( new_text, key, decode_bytes( iv_b64 ) ) )
      self.new( label, iv_b64, crypted_text_b64 )
    end

    # Decrypts secret message and returns it. Decryption will only succeed if the password is
    # the same as used to create the secret.
    # @param [String] key encryption key
    # @return [String] plaintext message originally saved into object
    def decrypt_text key
      decrypt_string decode_bytes( crypted_text ), key, decode_bytes( iv )
    end

    # Rebuilds secret with new plaintext, encrypting it using supplied password. The password can be
    # same or different to original one. The initial value for encryption
    # is re-generated automatically using SecureRandom (so even if key and message are identical
    # to original, the encryption will be different)
    # @param [String] new_plaintext plaintext version of new message
    # @param [String] password encryption key
    # @return [SecretStore::Secret] self
    def replace_text new_plaintext, key
      @iv = encode_bytes( SecureRandom.random_bytes(16) )
      @crypted_text = encode_bytes( encrypt_string( new_plaintext, key, decode_bytes( iv ) ) )
      self
    end

    # Serialise to a Hash. Inverse of .from_h
    # @return [Hash] serialised version of object
    def to_h
      Hash[
        :label => @label,
        :iv => @iv,
        :crypted_text => @crypted_text
      ]
    end

    # De-serialise from a Hash. Inverse of .to_h
    # @param [Hash] h as generated by .to_h
    # @return [SecretStore::Secret] new object
    def self.from_h h
      [:label, :iv, :crypted_text].each do |property|
        unless h.has_key? property
          raise "Missing hash key #{property}"
        end
      end

      self.new( h[:label], h[:iv], h[:crypted_text] )
    end
  end
end
