require 'sqlite3'
require 'yaml'

module SecretStore
  class Store
    attr_reader :db

    def initialize db_connect
      @db = SQLite3::Database.new( db_connect )
      create_tables
    end

    def save_password pw
      pw_hash = pw.to_h
      existing = db.execute( 'SELECT hashed_password FROM master_password WHERE id = 1' )
      if existing.empty?
        db.execute( 'INSERT INTO master_password (id, hashed_password) VALUES ( 1, ? )',
            hash_to_array( pw_hash, [:hashed_password] ) )
      else
        db.execute( 'UPDATE master_password SET hashed_password=? WHERE id=1',
            hash_to_array( pw_hash, [:hashed_password] ) )
      end
    end

    def load_password
      record = db.execute( 'SELECT hashed_password FROM master_password WHERE id = 1' ).first
      if record
        SecretStore::Password.from_h( array_to_hash( record, [:hashed_password] ) )
      end
    end

    def save_secret secret
      secret_hash = secret.to_h
      label = secret_hash[:label]
      existing = db.execute( 'SELECT label FROM secret WHERE label = ?', [label] )
      if existing.empty?
        db.execute( 'INSERT INTO secret (label,iv,pbkdf2_salt,crypted_text) VALUES (?,?,?,?)',
            hash_to_array( secret_hash, [:label,:iv,:pbkdf2_salt,:crypted_text] ) )
      else
        db.execute( 'UPDATE secret SET iv=?, pbkdf2_salt=?, crypted_text=? WHERE label=?',
            hash_to_array( secret_hash, [:iv,:pbkdf2_salt,:crypted_text,:label] ) )
      end
    end

    def load_secret label
      record = db.execute( 'SELECT label,iv,pbkdf2_salt,crypted_text FROM secret WHERE label = ?', [label] ).first
      if record
        SecretStore::Secret.from_h( array_to_hash record, [:label,:iv,:pbkdf2_salt,:crypted_text] )
      end
    end

    def delete_secret label
      db.execute( 'DELETE FROM secret WHERE label = ?', [label] )
    end

    def export_yaml yaml_file
      pw = load_password
      secrets = all_secrets
      all_data = Hash[
        :master_password => pw.to_h,
        :secrets => secrets.map { |s| s.to_h }
      ]

      File.open( yaml_file, 'wb' ) { |f| f.puts YAML.dump( all_data ) }
    end

    def self.import_yaml yaml_file, db_connect
      store = self.new( db_connect )
      all_data = YAML.load( File.read( yaml_file ) )

      if pw_hash = all_data[:master_password]
        pw = SecretStore::Password.from_h( pw_hash  )
        store.save_password pw
      end

      if secret_hashes = all_data[:secrets]
        secret_hashes.each do |secret_hash|
          secret = SecretStore::Secret.from_h( secret_hash )
          store.save_secret secret
        end
      end

      store
    end

    def all_secrets
      records = db.execute( 'SELECT label,iv,pbkdf2_salt,crypted_text FROM secret' )
      records.map do |record|
        SecretStore::Secret.from_h( array_to_hash record, [:label,:iv,:pbkdf2_salt,:crypted_text] )
      end
    end

    private

    def hash_to_array hash, keys
      keys.map { |k| hash[k] }
    end

    def array_to_hash array, keys
      Hash[ keys.zip(array) ]
    end

    def create_tables
      db.execute <<-SQL
        CREATE TABLE IF NOT EXISTS master_password (
        id INTEGER PRIMARY KEY,
        hashed_password TEXT NOT NULL);
      SQL

      db.execute <<-SQL
        CREATE TABLE IF NOT EXISTS secret (
        label VARCHAR(50) PRIMARY KEY,
        iv VARCHAR(20) NOT NULL,
        pbkdf2_salt VARCHAR(20) NOT NULL,
        crypted_text TEXT NOT NULL);
      SQL
    end
  end
end
