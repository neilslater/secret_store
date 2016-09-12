# Creates fixtures - need t update spec when new values are generated
require 'secret_store'

File.unlink('fixture_store.yml') if File.exists? 'fixture_store.yml'
File.unlink('fixture_store.dat') if File.exists? 'fixture_store.dat'

pw = SecretStore::Password.new( "$2a$14$El244JS41doLJakEQ/xDrOBEUkof8.TDo62qBrosgOg6n4KOukZyi", "1CgmW8jBemz001LcphM0tA==" )
key = Base64.urlsafe_decode64("zfOc-2CKnVA0l3vpIsZUr6lhgnGdBAuxcPIK_H9lsY4=")
secret1 = SecretStore::Secret.create_from_plaintext 'example', 'This is a secret!', key
secret2 = SecretStore::Secret.create_from_plaintext 'second', 'This is a second secret!', key

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
    SecretStore::Secret.new( 'example', '#{secret1.iv}', '#{secret1.crypted_text}', '#{secret1.auth_tag}' )
  }
  let(:example_plaintext_1) { 'This is a secret!' }

  let(:example_secret_2) {
    SecretStore::Secret.new( 'second', '#{secret2.iv}', '#{secret2.crypted_text}', '#{secret2.auth_tag}' )
  }
  let(:example_plaintext_2) { 'This is a second secret!' }
  RUBY
