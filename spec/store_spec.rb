require 'spec_helper'

describe SecretStore::Store do
  let(:example_password_text) { 'hidden' }
  let(:example_password) { SecretStore::Password.create( example_password_text ) }

  let(:example_secret_1) {
    SecretStore::Secret.new( 'example', 'UbJdZhd4MQQTvFf9OB3W6A==', 'mHv4-vrSLVpXMDmra6k-fg==', 'ZsjUIqTfvEaJok25n-kuwMi5lwOgYgZ3yyBai2lJEzA=' )
  }
  let(:example_plaintext_1) { 'This is a secret!' }

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
      it "writes password data to database" do
        subject.save_password example_password
        expect( subject.db.)
      end
    end

    describe "#load_password" do
      it "returns nil when there is no password" do
        expect( subject.load_password ).to be_nil
      end
    end

    describe "#save_secret" do

    end

    describe "#load_secret" do
      it "returns nil when there is no secret with matching label" do
        expect( subject.load_secret('example') ).to be_nil
        subject.save_secret( example_secret_1 )
        expect( subject.load_secret('anything_else') ).to be_nil
      end
    end
  end
end
