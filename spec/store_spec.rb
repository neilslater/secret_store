require 'spec_helper'
require 'fileutils'
require 'tempfile'

describe SecretStore::Store do
  let(:example_password_text) { "blubbery" }
  let(:example_password_hash) { "$2a$14$El244JS41doLJakEQ/xDrOBEUkof8.TDo62qBrosgOg6n4KOukZyi" }
  let(:example_pbkdf_salt) { "1CgmW8jBemz001LcphM0tA==" }
  let(:example_password) { SecretStore::Password.new(example_password_hash,example_pbkdf_salt) }

  let(:example_key) { Base64.urlsafe_decode64("zfOc-2CKnVA0l3vpIsZUr6lhgnGdBAuxcPIK_H9lsY4=") }

  let(:example_secret_1) {
    SecretStore::Secret.new( 'example', 'ot7vSPiwpd5DNscfHYJYAQ==', 'qMAKyAUcHoyeCBQN6Bx5Czc=', 'EdPjgVqJ6QnhjV3zkrCnBg==' )
  }
  let(:example_plaintext_1) { 'This is a secret!' }

  let(:example_secret_2) {
    SecretStore::Secret.new( 'second', '0t26DfXiwcVMaDEIUE1Lwg==', 'ssO1_-ioS5LS4sE2Ywf0k-k3iuJoQmHd', '6fVRTtuEbycHjEt1ktVHgA==' )
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
        expect( secret.decrypt_text(example_key)).to eql example_plaintext_1
      end
    end

    describe "#import_yaml" do
      let(:yaml_fixture) { File.join( File.dirname(__FILE__), 'fixture_store.yml' ) }

      it "creates a new store" do
        store = SecretStore::Store.import_yaml( yaml_fixture, ':memory:' )
        expect( store ).to be_a SecretStore::Store
      end

      it "imports data correctly" do
        store = SecretStore::Store.import_yaml( yaml_fixture, ':memory:' )
        expect( store.load_password.matches(example_password_text) ).to be true
        expect( store.load_secret('example').to_h ).to eql example_secret_1.to_h
        expect( store.load_secret('second').to_h ).to eql example_secret_2.to_h
      end
    end
  end

  describe "instance methods" do
    subject { SecretStore::Store.new( ':memory:' ) }

    def db_num_secrets
      subject.db.execute('SELECT count(*) FROM secret').first.first
    end

    def db_num_passwords
      subject.db.execute('SELECT count(*) FROM master_password').first.first
    end

    describe "#save_password" do
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

      it "returns password data when there is one" do
        subject.save_password example_password
        pw_from_store = subject.load_password
        expect( pw_from_store.to_h ).to eql example_password.to_h
      end
    end

    describe "#save_secret" do
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
        expect( first_secret.decrypt_text( example_key ) ).to eql example_plaintext_1

        second_secret = subject.load_secret('second')
        expect( second_secret ).to be_a SecretStore::Secret
        expect( second_secret.decrypt_text( example_key ) ).to eql example_plaintext_2
      end
    end

    describe "#delete_secret" do
      before :each do
        subject.save_secret( example_secret_1 )
        subject.save_secret( example_secret_2 )
      end

      it "makes no difference when there is no matching label" do
        subject.delete_secret('qwerty')

        expect( db_num_secrets ).to eql 2

        first_secret = subject.load_secret('example')
        expect( first_secret ).to be_a SecretStore::Secret
        expect( first_secret.decrypt_text( example_key ) ).to eql example_plaintext_1

        second_secret = subject.load_secret('second')
        expect( second_secret ).to be_a SecretStore::Secret
        expect( second_secret.decrypt_text( example_key ) ).to eql example_plaintext_2
      end

      it "removes an existing secret without affecting others" do
        subject.delete_secret('example')

        expect( db_num_secrets ).to eql 1

        first_secret = subject.load_secret('example')
        expect( first_secret ).to be_nil

        second_secret = subject.load_secret('second')
        expect( second_secret ).to be_a SecretStore::Secret
        expect( second_secret.decrypt_text( example_key ) ).to eql example_plaintext_2
      end
    end

    describe "#export_yaml" do
      before :each do
        @yaml_file = Tempfile.new('secret_store_test.yml').path
        @store = SecretStore::Store.new( File.join( File.dirname(__FILE__), 'fixture_store.dat' ) )
      end

      before :each do
        if File.exists?( @yaml_file )
          FileUtils.rm @yaml_file
        end
      end

      it "writes a file" do
        @store.export_yaml( @yaml_file )
        expect( File.size?(@yaml_file) ).to be > 200
      end

      it "saves YAML data to the file" do
        @store.export_yaml( @yaml_file )
        exported_data = YAML.load( File.read( @yaml_file ) )
        expect( exported_data ).to eql Hash[
          :master_password => Hash[
              :hashed_password => "$2a$14$El244JS41doLJakEQ/xDrOBEUkof8.TDo62qBrosgOg6n4KOukZyi",
              :pbkdf2_salt => "1CgmW8jBemz001LcphM0tA=="
          ],
          :secrets => [
            Hash[ :label=>"example", :iv=> 'ot7vSPiwpd5DNscfHYJYAQ==',
                  :crypted_text=> 'qMAKyAUcHoyeCBQN6Bx5Czc=', :auth_tag => 'EdPjgVqJ6QnhjV3zkrCnBg==' ]
          ]
        ]
      end
    end

    describe "#all_secrets" do
      it "returns empty array when there are no secrets in the store" do
        expect( subject.all_secrets ).to be_empty
      end

      it "returns array of all secrets in the store" do
        subject.save_secret( example_secret_1 )
        subject.save_secret( example_secret_2 )

        got_secrets = subject.all_secrets
        expect( got_secrets.count ).to eql 2

        expected_plaintexts = [ example_plaintext_1, example_plaintext_2 ]
        got_secrets.sort_by(&:label).zip( expected_plaintexts ).each do |secret, plaintext|
          expect( secret ).to be_a SecretStore::Secret
          expect( secret.decrypt_text( example_key ) ).to eql plaintext
        end
      end
    end
  end
end
