require 'spec_helper'

# Monkey patch for test purposes
class SecretStore::Connection
  def test_store
    @store
  end
end

describe SecretStore::Connection do
  let(:example_password) { 'hidden' }
  let(:example_plaintext_1) { 'This is a secret!' }
  let(:example_plaintext_2) { 'This is a second secret!' }
  let(:sqlite_fixture) { File.join( File.dirname(__FILE__), 'fixture_store.dat' ) }
  let(:yaml_fixture) { File.join( File.dirname(__FILE__), 'fixture_store.yml' ) }
  let(:store_fixture) { SecretStore::Store.import_yaml( yaml_fixture, ':memory:' ) }

  describe "class methods" do
    describe "#new" do
      it "connects to an existing store file" do
        connection = SecretStore::Connection.new( store_fixture, example_password )
        expect( connection ).to be_a SecretStore::Connection
      end

      it "fails to connect if the password is bad" do
        expect {
          SecretStore::Connection.new( store_fixture, 'wrong' )
        }.to raise_error RuntimeError, /password/
      end

      it "allows a new password on a new blank store" do
        store = SecretStore::Store.new( ':memory:' )
        connection = SecretStore::Connection.new( store, 'another-password' )
        expect( store.load_password.matches( 'another-password') ).to be true
      end
    end

    describe "#load" do
      it "connects to an existing store file" do
        connection = SecretStore::Connection.load( sqlite_fixture, example_password )
        expect( connection ).to be_a SecretStore::Connection
      end

      it "fails to connect if the password is bad" do
        expect {
          SecretStore::Connection.load( sqlite_fixture, 'wrong' )
        }.to raise_error RuntimeError, /password/
      end

      it "allows a new password on a new blank store" do
        connection = SecretStore::Connection.load( ':memory:', 'another-password' )
        expect( connection.test_store.load_password.matches( 'another-password') ).to be true
      end
    end

    describe "#init_from_yaml" do
      it "generates a new store and populates with YAML data" do
        connection = SecretStore::Connection.init_from_yaml( ':memory:', example_password, yaml_fixture )
        expect( connection ).to be_a SecretStore::Connection
        expect( connection.all_secret_labels ).to match_array ['example', 'second']
      end

      it "fails to import and connect if the password is bad" do
        expect {
          SecretStore::Connection.init_from_yaml( ':memory:', 'wrong-password', yaml_fixture )
        }.to raise_error RuntimeError, /password/
      end
    end
  end

  describe "instance methods" do
    subject { SecretStore::Connection.init_from_yaml( ':memory:', example_password, yaml_fixture ) }

    def num_secrets_in db
      db.execute('SELECT count(*) FROM secret').first.first
    end

    describe "#write_secret" do
      it "adds a new secret to the database, if the label is new" do
        db = subject.test_store.db
        expect {
          subject.write_secret 'new_label', 'New message'
        }.to change { num_secrets_in(db) }.by 1
      end

      it "adds the new secret so that it can be decrypted" do
        subject.write_secret 'new_label', 'New message'
        expect( subject.test_store.load_secret('new_label').decrypt_text(example_password) ).to eql 'New message'
      end

      it "over-writes an existing secret" do
        expect( subject.test_store.load_secret('example').decrypt_text(example_password) ).to eql example_plaintext_1
        subject.write_secret 'example', 'New message'
        expect( subject.test_store.load_secret('example').decrypt_text(example_password) ).to eql 'New message'

        db = subject.test_store.db
        expect( num_secrets_in(db) ).to eql 2
      end
    end

    describe "#read_secret" do
      it "decrypts secret from database" do
        expect( subject.read_secret('example') ).to eql example_plaintext_1
        expect( subject.read_secret('second') ).to eql example_plaintext_2
      end
    end

    describe "#delete_secret" do
      it "removes secret from database" do
        subject.delete_secret 'example'
        expect( subject.read_secret('example') ).to be_nil
        expect( subject.read_secret('second') ).to eql example_plaintext_2
      end
    end

    describe "all_secret_labels" do
      it "lists all known labels" do
        expect( subject.all_secret_labels ).to match_array %w(example second)
        subject.write_secret 'third', 'Third secret message'
        expect( subject.all_secret_labels ).to match_array %w(example second third)
      end
    end
  end
end
