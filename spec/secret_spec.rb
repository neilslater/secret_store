require 'spec_helper'

describe SecretStore::Secret do
  let(:example_label) { "example" }
  let(:example_iv) { "OnxLeMWx_KNDjLf2hS6qrw==" }
  let(:example_crypted_text) { "qEvVmafdSF-PYVxuutkkntU=" }
  let(:example_key) { Base64.urlsafe_decode64("zfOc-2CKnVA0l3vpIsZUr6lhgnGdBAuxcPIK_H9lsY4=") }
  let(:example_auth_tag) { "VcmfVqqQXq5at1M28tdTVw==" }

  let(:example_plaintext) { 'This is a secret!' }

  describe "class methods" do
    describe "#new" do
      it "creates valid, decryptable object" do
        secret = SecretStore::Secret.new( example_label, example_iv, example_crypted_text, example_auth_tag )
        expect( secret.decrypt_text( example_key ) ).to eql example_plaintext
      end
    end

    describe "#from_h" do
      it "creates valid, decryptable object from hash-based serialisation" do
        h = Hash[
          :label => example_label,
          :iv => example_iv,
          :crypted_text => example_crypted_text,
          :auth_tag => example_auth_tag
        ]
        secret = SecretStore::Secret.from_h( h )
        expect( secret.decrypt_text( example_key) ).to eql example_plaintext
      end
    end

    describe "#create_from_plaintext" do
      it "creates a valid, decryptable object" do
        secret = SecretStore::Secret.create_from_plaintext( example_label, example_plaintext, example_key )
        expect( secret.decrypt_text( example_key) ).to eql example_plaintext
      end

      it "uses a different initial value each time" do
        ivs = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext( example_label, example_plaintext, example_key )
          secret.iv
        end
        expect( ivs.uniq ).to eql ivs
      end

      it "has a different crypted text each time" do
        crypted_texts = [*0..10].map do
          secret = SecretStore::Secret.create_from_plaintext( example_label, example_plaintext, example_key )
          secret.crypted_text
        end
        expect( crypted_texts.uniq ).to eql crypted_texts
      end
    end
  end

  describe "instance methods" do
    subject { SecretStore::Secret.new( example_label, example_iv, example_crypted_text, example_auth_tag ) }

    describe "#decrypt_text" do
      it "works when the key is correct" do
        expect( subject.decrypt_text( example_key) ).to eql example_plaintext
      end

      it "raises error when the key is incorrect" do
        bad_passwords = ['', 'wrong', SecureRandom.random_bytes(32) ]
        bad_passwords.each do |bad_password|
          expect {
            subject.decrypt_text( bad_password )
          }.to raise_error OpenSSL::Cipher::CipherError
        end
      end

      it "does not change iv, crypted text or auth_tag" do
        expect( subject.decrypt_text( example_key) ).to eql example_plaintext

        expect( subject.iv ).to eql example_iv
        expect( subject.crypted_text ).to eql example_crypted_text
        expect( subject.auth_tag ).to eql example_auth_tag
      end
    end

    describe "#replace_text" do
      it "works using same key" do
        new_message = 'Another different secret!'
        subject.replace_text( new_message, example_key )
        expect( subject.decrypt_text( example_key) ).to eql new_message
      end

      it "works using a new key" do
        new_message = 'Another different secret!'
        new_key = SecureRandom.random_bytes(32)
        subject.replace_text( new_message, new_key )
        expect( subject.decrypt_text( new_key ) ).to eql new_message
      end

      it "changes iv, crypted text and auth_tag even if key and message are the same" do
        subject.replace_text( example_plaintext, example_key )
        expect( subject.decrypt_text( example_key) ).to eql example_plaintext

        expect( subject.iv ).to_not eql example_iv
        expect( subject.crypted_text ).to_not eql example_crypted_text
        expect( subject.auth_tag ).to_not eql example_auth_tag
      end
    end

    describe "#to_h" do
      it "serialises the object" do
        h = subject.to_h
        secret = SecretStore::Secret.from_h( h )
        expect( secret.decrypt_text( example_key ) ).to eql example_plaintext
        expect( subject.label ).to eql example_label
        expect( subject.iv ).to eql example_iv
        expect( subject.crypted_text ).to eql example_crypted_text
        expect( subject.auth_tag ).to eql example_auth_tag
      end
    end
  end
end
