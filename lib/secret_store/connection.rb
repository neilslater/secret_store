module SecretStore
  class Connection
    attr_reader :store

    def initialize store, password
      unless store.is_a? SecretStore::Store
        raise "Expected a SecretStore::Store, got #{store.inspect}"
      end
      @store = store
      @password = password.to_s
      verify_password
    end

    # Load store with existing password
    def self.load filename, password
      self.new( SecretStore::Store.new( filename ), password )
    end

    # Init new store from YAML dump
    def self.init_from_yaml filename, password, yaml_filename
      self.new( SecretStore::Store.import_yaml( yaml_filename, filename ), password )
    end

    def write_secret label, plaintext
      secret = SecretStore::Secret.create_from_plaintext( label, plaintext, password )
      store.save_secret( secret )
    end

    def read_secret label
      if secret = store.load_secret( label )
        secret.decrypt_text( password )
      end
    end

    def delete_secret label
      store.delete_secret( label )
    end

    def all_secret_labels
      store.all_secrets.map(&:label)
    end

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
