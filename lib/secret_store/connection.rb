# frozen_string_literal: true

module SecretStore
  # This class contains a database plus the encryption key for the database, for the convenience of
  # having a "connected" model and not needing to send the password or the derived key
  # as a parameter to every method.
  #
  # An instance of this class represents a single secret store plus the encryption key data for the
  # store.
  #
  class Connection
    # The connected store
    # @return [SecretStore::Store]
    attr_reader :store

    # Combines store with master password so that secrets can be encrypted and decrypted on demand.
    # @param [SecretStore::Store] store connected database
    # @param [String] password_text master password for the database
    # @return [SecretStore::Connection] connected database with password set for decryption
    #
    def initialize(store, password_text)
      raise "Expected a SecretStore::Store, got #{store.inspect}" unless store.is_a? SecretStore::Store

      @store = store
      @password = ensure_password(password_text)
    end

    # Connects to existing database file or creates new database.
    # @param [String] filename path to SQLite 3 database
    # @param [String] password_text master password for the database
    # @return [SecretStore::Connection] connected database with password set for decryption
    #
    def self.load(filename, password_text)
      new(SecretStore::Store.new(filename), password_text)
    end

    # Creates new store by importing YAML file, then connecting to the resulting SQLite 3 database.
    # If the password is incorrect, then the database is still created
    # @param [String] filename path to SQLite 3 database to be created
    # @param [String] password_text master password for the database, must match that in the YAML
    # @param [String] yaml_filename path to YAML backup of database
    # @return [SecretStore::Connection] connected database with password set for decryption
    #
    def self.init_from_yaml(filename, password_text, yaml_filename)
      # TODO: Should we check password first, from the YAML?
      new(SecretStore::Store.import_yaml(yaml_filename, filename), password_text)
    end

    # Stores a secret securely in the database, over-writing any existing secret with the same label.
    # @param [String] label identifier for secret
    # @param [String] plaintext content of secret
    # @return [SecretStore::Secret] the new or updated secret, including encrypted text
    #
    def write_secret(label, plaintext)
      secret = SecretStore::Secret.create_from_plaintext(label, plaintext, encrypt_checksum)
      store.save_secret(secret)
      secret
    end

    # Reads a secret from the database.
    # @param [String] label identifier for secret
    # @return [String,nil] the plaintext content of secret or nil if no secret exists with that label
    #
    def read_secret(label)
      if secret = store.load_secret(label)
        secret.decrypt_text(encrypt_checksum)
      end
    end

    # Deletes a secret from the database.
    # @param [String] label identifier for secret
    # @return [nil]
    #
    def delete_secret(label)
      store.delete_secret(label)
      nil
    end

    # Fetches labels for all secrets from the database
    # @return [Array<String>] all labels for secrets defined in the store
    #
    def all_secret_labels
      store.all_secrets.map(&:label)
    end

    # Changes the master password, re-encrypting all secrets to match. Warning, once disconnected the
    # new text password will be required to access any secrets.
    # @param [String] new_password_text new master password
    # @return [SecretStore::Password] secure hash representation of the password, as stored in the database
    #
    def change_password(new_password_text)
      raise 'Password too short. Minimum 8 characters.' if new_password_text.length < 8

      new_password = SecretStore::Password.create(new_password_text)
      new_encrypt_checksum = new_password.activate_checksum(new_password_text)
      store.all_secrets.each do |old_secret|
        plaintext = old_secret.decrypt_text(encrypt_checksum)
        new_secret = SecretStore::Secret.create_from_plaintext(old_secret.label, plaintext, new_encrypt_checksum)
        store.save_secret(new_secret)
      end

      store.save_password(new_password)

      @password = new_password
    end

    private

    def encrypt_checksum
      @password.checksum
    end

    def ensure_password(password_text)
      if pw = store.load_password
        pw.activate_checksum password_text
      else
        raise 'Password too short. Minimum 8 characters.' if password_text.length < 8

        pw = SecretStore::Password.create(password_text)
        store.save_password(pw)
        pw.activate_checksum password_text
      end
      pw
    end
  end
end
