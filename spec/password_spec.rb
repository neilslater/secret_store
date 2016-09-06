require 'spec_helper'

describe SecretStore::Password do
  let(:example_password) { "blubbery" }
  let(:example_password_hash) { "$2a$14$El244JS41doLJakEQ/xDrOBEUkof8.TDo62qBrosgOg6n4KOukZyi" }
  let(:example_pbkdf_salt) { "1CgmW8jBemz001LcphM0tA==" }
  let(:example_key) { Base64.urlsafe_decode64("zfOc-2CKnVA0l3vpIsZUr6lhgnGdBAuxcPIK_H9lsY4=") }

  describe "class methods" do
    describe "#new" do
      it "creates valid object from good password hash" do
        expect( SecretStore::Password.new( example_password_hash, example_pbkdf_salt ) ).to be_a SecretStore::Password
      end

      it "does not create a Password object from Strings which are not password hashes" do
        bad_pw_hashes = ['','hello','Secret','nil']
        bad_pw_hashes.each do |bad_pw_hash|
          expect {
            SecretStore::Password.new( bad_pw_hash, example_pbkdf_salt )
          }.to raise_error BCrypt::Errors::InvalidHash
        end
      end
    end

    describe "#create" do
      it "creates new object" do
        expect( SecretStore::Password.create( 'super-secret' ) ).to be_a SecretStore::Password
      end

      it "matches to original password" do
        pw = SecretStore::Password.create( 'super-secret' )
        expect( pw.matches( 'super-secret') ).to be true
      end
    end

    describe "#from_h" do
      it "creates valid object from serialisation" do
        h = Hash[ :hashed_password => example_password_hash, :pbkdf2_salt => example_pbkdf_salt ]
        expect( SecretStore::Password.from_h( h ) ).to be_a SecretStore::Password
      end
    end
  end

  describe "instance methods" do
    subject { SecretStore::Password.new( example_password_hash, example_pbkdf_salt ) }

    describe "#matches" do
      it "returns true for correct plaintext password" do
        expect( subject.matches(example_password) ).to be true
      end

      it "returns false for incorrect passwords" do
        bad_pws = [nil, '', 'frej', 'password']
        bad_pws.each do |bad_pw|
          expect( subject.matches(bad_pw) ).to be false
        end
      end
    end

    describe "#activate_key" do
      it "generates correct key value" do
        expect( subject.activate_key(example_password) ).to eql example_key
      end

      it "sets key property" do
        subject.activate_key(example_password)
        expect( subject.key ).to eql example_key
      end

      it "raises error for incorrect passwords" do
        bad_pws = [nil, '', 'password', example_key, example_password_hash, example_pbkdf_salt]
        bad_pws.each do |bad_pw|
          expect {
            subject.activate_key(bad_pw)
          }.to raise_error RuntimeError, /password/
        end
      end
    end

    describe "#to_h" do
      it "returns a Hash" do
        expect( subject.to_h ).to be_a Hash
      end

      it "can be passed into SecretStore::Password.from_h to re-create same password" do
        serialised = subject.to_h
        deserialised = SecretStore::Password.from_h( serialised )
        expect( deserialised.matches(example_password) ).to be true
        expect( deserialised.activate_key(example_password) ).to eql example_key
      end
    end
  end
end
