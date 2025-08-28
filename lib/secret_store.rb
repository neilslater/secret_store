# frozen_string_literal: true

require 'bcrypt'
require 'io/console'
require 'secret_store/version'
require 'secret_store/core'
require 'secret_store/secret'
require 'secret_store/password'
require 'secret_store/store'
require 'secret_store/connection'

# Top-level methods in this module are imported into main Object in the console application. They
# are all based on creating and using a SecretStore::Connection object for accessing and managing
# the store and its contents.
#
# @example Getting a secret
#  read_secret 'google'
#  # => "my_google_password"
#
module SecretStore
  # Default SQLite 3 database file name, based on SECRET_STORE_FILE environment variable if it is
  # set, otherwise will be 'secrets.sqlite3.dat' in user's home directory.
  # @return [String] full path to file.
  #
  def default_secrets_file
    ENV['SECRET_STORE_FILE'] || File.join(ENV['HOME'], 'secrets.sqlite3.dat')
  end

  # Default YAML file name for exports, based on SECRET_EXPORT_FILE environment variable if it is
  # set, otherwise will be 'secrets_export.yml' in user's home directory.
  # @return [String] full path to file.
  #
  def default_backup_file
    ENV['SECRET_EXPORT_FILE'] || File.join(ENV['HOME'], 'secrets_export.yml')
  end

  # Prompts for password and attempts connection to a SecretStore SQLite 3 database. If the database
  # does not exist, then it will be created and a record for the master password created.
  # @param [String] secrets_file path to SQLite 3 database containing secrets
  # @return [SecretStore::Connection] connected secret store
  #
  def connect_secret_store(secrets_file = default_secrets_file)
    print 'Password: '
    password = $stdin.noecho(&:gets).chomp
    puts '*' * password.length
    @connection = SecretStore::Connection.load(secrets_file, password)
  end

  # Saves a YAML copy of the database, with binary values Base64 encoded (URL safe variant)
  # @param [String] filename path to write YAML file
  # @return [String] value used for filename
  #
  def export_secrets(filename = default_backup_file)
    @connection.store.export_yaml filename
    filename
  end

  # Creates or updates secret associated with a given label.
  # @param [String] label identifier for the secret
  # @param [String] content plaintext value of the secret, which will be encrypted and stored
  # @return [nil]
  #
  def write_secret(label, content)
    @connection.write_secret label.to_s, content
    nil
  end

  # Reads secret associated with given label.
  # @param [String] label identifier for the secret
  # @return [String] plaintext value of the secret, as decrypted from the store
  #
  def read_secret(label)
    @connection.read_secret label.to_s
  end

  # Deletes secret associated with given label.
  # @param [String] label identifier for the secret
  # @return [nil]
  #
  def delete_secret(label)
    @connection.delete_secret label.to_s
    nil
  end

  # Fetches labels for all secrets
  # @return [Array<String>] all labels for secrets defined in the store
  #
  def all_secret_labels
    @connection.all_secret_labels
  end

  # Prompts (twice) for new password and changes master password. This involves generating a new
  # password hash plus decrypting then re-encrypting all secrets, so can take a little while.
  # @return [nil]
  #
  def change_password
    print 'New password: '
    new_password = $stdin.noecho(&:gets).chomp
    puts '*' * new_password.length

    print 'Repeat new password: '
    verify_new_password = $stdin.noecho(&:gets).chomp
    puts '*' * verify_new_password.length

    raise 'Passwords do not match' if new_password != verify_new_password

    @connection.change_password new_password

    nil
  end

  # Reads bank passwords (starting from `pw:`) and outputs the characters at given positions.
  # @param [String] label identifier for the secret
  # @param [Array<Integer>] idx positons to output
  # @return [String] characters to enter for login
  #
  def bank_login label, *idx
    text = @connection.read_secret label.to_s
    pw = ' ' + text.match(/pw:\s*([a-zA-Z0-9_-]+)/i)[1]
    pw.chars.values_at(*idx).join(' ')
  end

  # Prints basic summary of SecretStore methods.
  # @return [nil]
  #
  def help!
    puts 'SecretStore methods available:'
    puts "  read_secret 'label'"
    puts "  write_secret 'label', 'content'"
    puts "  delete_secret 'label'"
    puts '  all_secret_labels'
    puts '  change_password'
    puts "  export_secrets ['export_yaml_file']"
  end
end
