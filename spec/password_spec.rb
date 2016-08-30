require 'spec_helper'

describe SecretStore::Password do
  let(:example_password) { "freg" }
  let(:example_password_hash) { "$2a$14$jatN73yCN3A0WdoeaGyyE.pL3YJZoC1qAEuS0txU9LlNwRBbIiGkm" }

  describe "class methods" do
    describe "#new" do
      it "creates valid object from good password hash" do
        expect( SecretStore::Password.new( example_password_hash ) ).to be_a SecretStore::Password
      end

      it "does not create a Password object from Strings which are not password hashes" do
        bad_pw_hashes = ['','hello','Secret','nil']
        bad_pw_hashes.each do |bad_pw_hash|
          expect {
            SecretStore::Password.new( bad_pw_hash )
          }.to raise_error BCrypt::Errors::InvalidHash
        end
      end
    end

    describe "#from_h" do
      it "creates valid object from serialisation" do
        h = Hash[ :hashed_password => example_password_hash ]
        expect( SecretStore::Password.from_h( h ) ).to be_a SecretStore::Password
      end
    end
  end

  describe "instance methods" do
    subject { SecretStore::Password.new( example_password_hash ) }

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

    describe "#to_h" do
      it "returns a Hash" do
        expect( subject.to_h ).to be_a Hash
      end

      it "can be passed into SecretStore::Password.from_h to re-create same password" do
        serialised = subject.to_h
        deserialised = SecretStore::Password.from_h( serialised )
        expect( deserialised.matches(example_password) ).to be true
      end
    end
  end
end
