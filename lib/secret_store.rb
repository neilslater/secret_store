require 'bcrypt'
require "secret_store/version"
require "secret_store/core"
require "secret_store/secret"
require "secret_store/password"
require "secret_store/store"
require "secret_store/connection"

module SecretStore
  def default_secrets_file
    ENV['SECRET_STORE_FILE'] || File.join( ENV['HOME'], 'secrets.sqlite3.dat' )
  end

  def connect_secret_store secrets_file
    print "Password: "
    password = STDIN.noecho(&:gets).chomp
    puts
    @connection = SecretStore::Connection.load( secrets_file, password )
  end

  def write_secret label, content
    @connection.write_secret label, content
  end

  def read_secret label
    @connection.read_secret label
  end

  def delete_secret label
    @connection.delete_secret label
  end

  def all_secret_labels
    @connection.all_secret_labels
  end

  def change_password
    print "New password: "
    new_password = STDIN.noecho(&:gets).chomp
    puts

    print "Repeat new password: "
    verify_new_password = STDIN.noecho(&:gets).chomp
    puts

    if new_password != verify_new_password
      raise "Passwords do not match"
    end

    @connection.change_password new_password

    nil
  end
end
