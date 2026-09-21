# frozen_string_literal: true

require 'tempfile'

module SecretStore
  # Publishes complete, private YAML backups without replacing database files or their aliases.
  class BackupFile
    # Capture the target and the connection's database/sidecar paths.
    # @param [SecretStore::Store] store source database
    # @param [String] filename output filename
    # @return [SecretStore::BackupFile]
    def initialize(store, filename)
      @store = store
      @target = File.join(File.realpath(File.dirname(filename)), File.basename(filename))
      @protected = store.db.execute('PRAGMA database_list').flat_map do |record|
        record[2].empty? ? [] : ['', '-journal', '-wal', '-shm'].map { |suffix| record[2] + suffix }
      end
    end

    # Take a coherent snapshot, serialize fully, then atomically replace the backup.
    # The temporary file is flushed and fsynced before rename. Directory fsync and universal
    # power-loss durability are not promised; publication assumes same-filesystem rename semantics.
    # @return [nil]
    def write
      validate_target
      serialized = YAML.dump(snapshot)
      Tempfile.create(['.secret-store-', '.tmp'], File.dirname(@target)) do |file|
        write_contents(file, serialized)
        validate_target
        File.rename(file.path, @target)
      end
      nil
    end

    private

    def snapshot
      @store.transaction(:deferred) do
        { master_password: @store.load_password&.to_h, secrets: @store.all_secrets.map(&:to_h) }
      end
    end

    def write_contents(file, serialized)
      file.chmod(0o600)
      file.binmode
      file.write(serialized)
      file.flush
      file.fsync
      file.close
    end

    def validate_target
      validate_existing_target
      collision = @protected.any? { |path| File.expand_path(path) == @target || File.identical?(path, @target) }
      raise 'Backup destination is a database or SQLite sidecar' if collision
    end

    def validate_existing_target
      stat = File.lstat(@target)
      raise 'Backup destination must be a regular file, not a symlink' unless stat.file?
      raise 'Backup destination must be owned by the current user' unless stat.uid == Process.euid
    rescue Errno::ENOENT
      # An absent target is safe to create after validating its database identity.
    end
  end
end
