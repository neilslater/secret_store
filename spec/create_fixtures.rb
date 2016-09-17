# Creates fixtures - need t update spec when new values are generated
require 'secret_store'

File.unlink('fixture_store.yml') if File.exists? 'fixture_store.yml'
File.unlink('fixture_store.dat') if File.exists? 'fixture_store.dat'

pw = SecretStore::Password.new( "$2a$14$.WO3JtKxNhzlASL4eQpkEO", "rCLPwKKsFb5WwgY1y0LwAQ==",
    "9_ZGG1_mabi9Q5qvxu4sOA== ~ k4TSdX28eTImvdDmzhtju-87-35msJBPilU_25JG6UE= ~ dKxORrEkMFsW_uAsr3fGHA==" )
checksum = "3EG3i1.oq1T5cmZVlq.cnOt28gz6U8G"
secret1 = SecretStore::Secret.create_from_plaintext 'example', 'This is a secret!', checksum
secret2 = SecretStore::Secret.create_from_plaintext 'second', 'This is a second secret!', checksum

store = SecretStore::Store.new( 'fixture_store.dat' )
store.save_password pw
store.save_secret secret1

store = SecretStore::Store.new( ':memory:' )
store.save_password pw
store.save_secret secret1
store.save_secret secret2
store.export_yaml 'fixture_store.yml'

puts <<-RUBY
  let(:example_secret_1) {
    SecretStore::Secret.new( 'example', '#{secret1.iv}', '#{secret1.pbkdf2_salt}', '#{secret1.crypted_text}', '#{secret1.auth_tag}' )
  }
  let(:example_plaintext_1) { 'This is a secret!' }

  let(:example_secret_2) {
    SecretStore::Secret.new( 'second', '#{secret2.iv}', '#{secret2.pbkdf2_salt}', '#{secret2.crypted_text}', '#{secret2.auth_tag}' )
  }
  let(:example_plaintext_2) { 'This is a second secret!' }
  RUBY
