# frozen_string_literal: true

module SecretStore
  # Prepares ordinary SQLite files with private permissions without chmodding existing files.
  module DatabaseFile
    # Exclusively create a private file, or preserve an existing regular file and its mode.
    # SQLite memory and temporary databases require no persistent pathname.
    # @param [String,Pathname] filename ordinary database path, :memory:, or an empty string
    # @return [nil]
    def self.prepare(filename)
      path = File.path(filename)
      raise ArgumentError, 'SQLite file: URIs are unsupported; use an ordinary filename' if path.start_with?('file:')
      return if path.empty? || path == ':memory:'

      File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.chmod(0o600) }
      nil
    rescue Errno::EEXIST
      raise ArgumentError, 'Database path must refer to a regular file' unless File.file?(path)
    end
  end
end
