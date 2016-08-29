require 'spec_helper'

describe SecretStore::Secret do
  let(:example_label) { "example" }
  let(:example_iv) { "UbJdZhd4MQQTvFf9OB3W6A==" }
  let(:example_pbkdf2_salt) { "mHv4-vrSLVpXMDmra6k-fg==" }
  let(:example_crypted_text) { "ZsjUIqTfvEaJok25n-kuwMi5lwOgYgZ3yyBai2lJEzA=" }

  let(:example_password) { 'hidden' }
  let(:example_plaintext) { 'This is a secret!' }

  describe "class methods" do
    describe "#new" do
      it "creates valid, decryptable object" do
        secret = SecretStore::Secret.new( example_label, example_iv, example_pbkdf2_salt, example_crypted_text )
        expect( secret.decrypt_text( example_password ) ).to eql example_plaintext
      end
    end

    describe "#from_h" do
      it "creates valid, decryptable object from hash-based serialisation" do
        h = Hash[
          :label => example_label,
          :iv => example_iv,
          :pbkdf2_salt => example_pbkdf2_salt,
          :crypted_text => example_crypted_text
        ]
        secret = SecretStore::Secret.from_h( h )
        expect( secret.decrypt_text( example_password ) ).to eql example_plaintext
      end
    end

    describe "#create_from_plaintext" do
      it "creates valid, decryptable object" do
        secret = SecretStore::Secret.create_from_plaintext( example_label, example_plaintext, example_password )
        expect( secret.decrypt_text( example_password ) ).to eql example_plaintext
      end

      it "uses a different initial value each time" do
        ivs = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext( example_label, example_plaintext, example_password )
          secret.iv
        end
        expect( ivs.uniq ).to eql ivs
      end

      it "has a different crypted text each time" do
        crypted_texts = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext( example_label, example_plaintext, example_password )
          secret.crypted_text
        end
        expect( crypted_texts.uniq ).to eql crypted_texts
      end

      it "has a different pbkdf2_salt each time" do
        salts = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext( example_label, example_plaintext, example_password )
          secret.pbkdf2_salt
        end
        expect( salts.uniq ).to eql salts
      end
    end
  end

  describe "instance methods" do
    subject { SecretStore::Secret.new( example_label, example_iv, example_pbkdf2_salt, example_crypted_text ) }

    describe "#decrypt_text" do
      it "works when the password is correct" do
        expect( subject.decrypt_text( example_password ) ).to eql example_plaintext
      end

      it "raises error when the password is incorrect" do
        bad_passwords = ['', 'wrong', '21357451782478' ]
        bad_passwords.each do |bad_password|
          expect {
            subject.decrypt_text( bad_password )
          }.to raise_error OpenSSL::Cipher::CipherError
        end
      end

      it "does not change iv, pbkdf2_salt, or crypted text" do
        expect( subject.decrypt_text( example_password ) ).to eql example_plaintext

        expect( subject.iv ).to eql example_iv
        expect( subject.pbkdf2_salt ).to eql example_pbkdf2_salt
        expect( subject.crypted_text ).to eql example_crypted_text
      end
    end

    describe "#replace_text" do
      it "works using same password" do
        new_message = 'Another different secret!'
        subject.replace_text( new_message, example_password )
        expect( subject.decrypt_text( example_password ) ).to eql new_message
      end

      it "works using a new password" do
        new_message = 'Another different secret!'
        new_password = 'thing'
        subject.replace_text( new_message, new_password )
        expect( subject.decrypt_text( new_password ) ).to eql new_message
      end

      it "changes iv, pbkdf2_salt, and crypted text even if password and message are the same" do
        subject.replace_text( example_plaintext, example_password )
        expect( subject.decrypt_text( example_password ) ).to eql example_plaintext

        expect( subject.iv ).to_not eql example_iv
        expect( subject.pbkdf2_salt ).to_not eql example_pbkdf2_salt
        expect( subject.crypted_text ).to_not eql example_crypted_text
      end
    end

    describe "#to_h" do
      it "serialises the object" do
        h = subject.to_h
        secret = SecretStore::Secret.from_h( h )
        expect( secret.decrypt_text( example_password ) ).to eql example_plaintext
        expect( subject.label ).to eql example_label
        expect( subject.iv ).to eql example_iv
        expect( subject.pbkdf2_salt ).to eql example_pbkdf2_salt
        expect( subject.crypted_text ).to eql example_crypted_text
      end
    end
  end
end
