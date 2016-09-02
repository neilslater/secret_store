require 'spec_helper'

describe SecretStore::Store do
  let(:example_password_text) { 'hidden' }
  let(:example_password) { SecretStore::Password.create( example_password_text ) }

  let(:example_secret_1) {
    SecretStore::Secret.new( 'example', 'UbJdZhd4MQQTvFf9OB3W6A==', 'mHv4-vrSLVpXMDmra6k-fg==', 'ZsjUIqTfvEaJok25n-kuwMi5lwOgYgZ3yyBai2lJEzA=' )
  }
  let(:example_plaintext_1) { 'This is a secret!' }

  let(:example_secret_2) {
    SecretStore::Secret.new( 'second', 'ImaXJ_i8aWxPRXw9LmC8kQ==', '_GjzDCahPOhW5xW27h89oQ==', 'ZLBiEo7llBb1m9h9mrGxtEmGtXWLzog0u2td2Cp1bjk=')
  }
  let(:example_plaintext_2) { 'This is a second secret!' }

  describe "class methods" do
    describe "#new" do
      it "creates valid store from scratch" do
        store = SecretStore::Store.new( ':memory:' )
        expect( store ).to be_a SecretStore::Store
      end

      it "creates valid store from existing file without deleting anything" do
        store = SecretStore::Store.new( File.join( File.dirname(__FILE__), 'fixture_store.dat' ) )
        expect( store ).to be_a SecretStore::Store
        pw = store.load_password
        expect( pw ).to be_a SecretStore::Password
        expect( pw.matches(example_password_text) ).to be true
        secret = store.load_secret('example')
        expect( secret ).to be_a SecretStore::Secret
        expect( secret.decrypt_text(example_password_text)).to eql example_plaintext_1
      end
    end
  end

  describe "instance methods" do
    subject { SecretStore::Store.new( ':memory:' ) }

    describe "#save_password" do
      def db_num_passwords
        subject.db.execute('SELECT count(*) FROM master_password').first.first
      end

      it "writes password data to database" do
        expect( db_num_passwords ).to eql 0
        subject.save_password example_password
        expect( db_num_passwords ).to eql 1
      end

      it "is idempotent" do
        expect( db_num_passwords ).to eql 0
        5.times { subject.save_password example_password }
        expect( db_num_passwords ).to eql 1
      end
    end

    describe "#load_password" do
      it "returns nil when there is no password" do
        expect( subject.load_password ).to be_nil
      end
    end

    describe "#save_secret" do
      def db_num_secrets
        subject.db.execute('SELECT count(*) FROM secret').first.first
      end

      it "adds new secret to database" do
        expect( db_num_secrets ).to eql 0
        subject.save_secret( example_secret_1 )
        expect( db_num_secrets ).to eql 1
      end

      it "is idempotent" do
        expect( db_num_secrets ).to eql 0
        5.times { subject.save_secret( example_secret_1 ) }
        expect( db_num_secrets ).to eql 1
      end

      it "adds new serets indexed by the label" do
        expect( db_num_secrets ).to eql 0
        subject.save_secret( example_secret_1 )
        expect( db_num_secrets ).to eql 1
        subject.save_secret( example_secret_2 )
        expect( db_num_secrets ).to eql 2
      end
    end

    describe "#load_secret" do
      it "returns nil when there is no secret with matching label" do
        expect( subject.load_secret('example') ).to be_nil
        subject.save_secret( example_secret_1 )
        expect( subject.load_secret('anything_else') ).to be_nil
      end

      it "returns a new valid secret when extracted by label" do
        subject.save_secret( example_secret_1 )
        subject.save_secret( example_secret_2 )

        first_secret = subject.load_secret('example')
        expect( first_secret ).to be_a SecretStore::Secret
        expect( first_secret.decrypt_text( example_password_text ) ).to eql example_plaintext_1

        second_secret = subject.load_secret('second')
        expect( second_secret ).to be_a SecretStore::Secret
        expect( second_secret.decrypt_text( example_password_text ) ).to eql example_plaintext_2
      end
    end
  end
end
