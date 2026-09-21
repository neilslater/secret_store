# frozen_string_literal: true

module SecretStore
  # A structurally validated encrypted archive, optionally authenticated before installation.
  # This format does not authenticate completeness, deletion, or rollback of valid records.
  class Restoration
    # Read a symbol-keyed archive using the safe YAML loader.
    # @param [String] filename YAML input path
    # @return [SecretStore::Restoration] validated archive
    def self.read(filename)
      new(YAML.safe_load_file(filename, permitted_classes: [Symbol]))
    end

    # Validate the entire envelope and every record before opening a destination.
    # @param [Hash] data serialized archive
    # @return [SecretStore::Restoration]
    def initialize(data)
      validate_envelope(data)
      @secrets = data.fetch(:secrets, []).map { |record| Secret.from_h(record) }
      material = data[:master_password]
      @password = Password.from_h(material) unless material.nil? || material == {}
      validate_relationships
    end

    # Authenticate the password and all records, or prepare a password for an empty archive.
    # @param [String] password_text master password
    # @return [SecretStore::Restoration] self
    def authenticate(password_text)
      @password ||= new_password(password_text)
      checksum = @password.activate_checksum(password_text)
      @secrets.each { |secret| secret.decrypt_text(checksum) }
      self
    end

    # Install into an empty store under an immediate transaction. An installation failure
    # closes the owned handle and rolls back records, but retains any newly initialized file.
    # @param [String] destination SQLite filename or :memory:
    # @return [SecretStore::Store] restored store, owned by the caller
    def restore(destination)
      store = Store.new(destination)
      store.transaction do
        raise 'Restoration requires an empty destination' unless store.empty?

        store.save_password(@password) if @password
        @secrets.each { |secret| store.save_secret(secret) }
      end
      completed = true
      store
    ensure
      store.db.close if store && !completed
    end

    private

    def validate_envelope(data)
      raise FormatError, 'archive must be a Hash' unless data.is_a?(Hash)
      raise FormatError, 'archive has unexpected keys' unless (data.keys - %i[master_password secrets]).empty?
      raise FormatError, 'secrets must be an Array' unless data.fetch(:secrets, []).is_a?(Array)
    end

    def validate_relationships
      raise FormatError, 'secrets require a master_password' if !@secrets.empty? && !@password

      labels = @secrets.map(&:label)
      raise FormatError, 'secrets must have unique labels' unless labels.uniq.length == labels.length
    end

    def new_password(password_text)
      valid = password_text.is_a?(String) && password_text.length >= 8
      raise 'Password too short. Minimum 8 characters.' unless valid

      Password.create(password_text)
    end
  end
end
