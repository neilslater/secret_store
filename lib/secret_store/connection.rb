module SecretStore
  class Connection
    # The connected store
    # @return [SecretStore::Store]
    attr_reader :store

    # Combines store with master password so that secrets can be encrypted and decrypted on demand.
    # @param [SecretStore::Store] store connected database
    # @param [String] password master password for the database
    # @return [SecretStore::Connection] connected database with password set for decryption
    #
    def initialize store, password
      unless store.is_a? SecretStore::Store
        raise "Expected a SecretStore::Store, got #{store.inspect}"
      end
      @store = store
      @password = password.to_s
      verify_password
    end

    # Connects to existing database file or creates new database.
    # @param [String] filename path to SQLite 3 database
    # @param [String] password master password for the database
    # @return [SecretStore::Connection] connected database with password set for decryption
    #
    def self.load filename, password
      self.new( SecretStore::Store.new( filename ), password )
    end

    # Creates new store by importing YAML file, then connecting to the resulting SQLite 3 database.
    # If the password is incorrect, then the database is still created
    # @param [String] filename path to SQLite 3 database to be created
    # @param [String] password master password for the database, must match that in the YAML
    # @param [String] filename path to YAML backup of database
    # @return [SecretStore::Connection] connected database with password set for decryption
    #
    def self.init_from_yaml filename, password, yaml_filename
      # TODO: Should we check password first, from the YAML?
      self.new( SecretStore::Store.import_yaml( yaml_filename, filename ), password )
    end

    # Stores a secret securely in the database, over-writing any existing secret with the same label.
    # @param [String] label identifier for secret
    # @param [String] plaintext content of secret
    # @return [SecretStore::Secret] the new or updated secret, including encrypted text
    #
    def write_secret label, plaintext
      secret = SecretStore::Secret.create_from_plaintext( label, plaintext, password )
      store.save_secret( secret )
      secret
    end

    # Reads a secret from the database.
    # @param [String] label identifier for secret
    # @return [String,nil] the plaintext content of secret or nil if no secret exists with that label
    #
    def read_secret label
      if secret = store.load_secret( label )
        secret.decrypt_text( password )
      end
    end

    # Deletes a secret from the database.
    # @param [String] label identifier for secret
    # @return [nil]
    #
    def delete_secret label
      store.delete_secret( label )
      nil
    end

    # Fetches labels for all secrets from the database
    # @return [Array<String>] all labels for secrets defined in the store
    #
    def all_secret_labels
      store.all_secrets.map(&:label)
    end

    # Changes the master password, re-encrypting all secrets to match. Warning, once disconnected the
    # new password will be required to access any secrets.
    # @param [String] new_password new master password
    # @return [SecretStore::Password] secure hash representation of the password, as stored in the database
    #
    def change_password new_password
      if new_password.length < 8
        raise "Password too short. Minimum 8 characters."
      end

      store.all_secrets.each do |old_secret|
        plaintext = old_secret.decrypt_text( password )
        new_secret = SecretStore::Secret.create_from_plaintext( old_secret.label, plaintext, new_password )
        store.save_secret( new_secret )
      end

      pw = SecretStore::Password.create( new_password )
      store.save_password( pw )

      @password = new_password
    end

    private

    def password
      @password
    end

    def verify_password
      if pw = store.load_password
        if pw.matches( password )
          return nil
        else
          raise "Incorrect password, connection failed"
        end
      else
        if password.length < 8
          raise "Password too short. Minimum 8 characters."
        end
        pw = SecretStore::Password.create( password )
        store.save_password( pw )
      end
    end
  end
end
