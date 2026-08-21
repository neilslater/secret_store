# frozen_string_literal: true

# Creates fixtures; update the matching specs when new values are generated.
require_relative '../lib/secret_store'
require 'fileutils'

fixture_directory = File.expand_path('../spec', __dir__)
yaml_fixture = File.join(fixture_directory, 'fixture_store.yml')
sqlite_fixture = File.join(fixture_directory, 'fixture_store.dat')
FileUtils.rm_f(yaml_fixture)
FileUtils.rm_f(sqlite_fixture)

password_encryption = [
  '9_ZGG1_mabi9Q5qvxu4sOA==',
  'k4TSdX28eTImvdDmzhtju-87-35msJBPilU_25JG6UE=',
  'dKxORrEkMFsW_uAsr3fGHA=='
].join(' ~ ')
password = SecretStore::Password.new('$2a$14$.WO3JtKxNhzlASL4eQpkEO', 'rCLPwKKsFb5WwgY1y0LwAQ==',
                                     password_encryption)
checksum = '3EG3i1.oq1T5cmZVlq.cnOt28gz6U8G'
primary_secret = SecretStore::Secret.create_from_plaintext 'example', 'This is a secret!', checksum
secondary_secret = SecretStore::Secret.create_from_plaintext 'second', 'This is a second secret!', checksum

store = SecretStore::Store.new(sqlite_fixture)
store.save_password password
store.save_secret primary_secret

store = SecretStore::Store.new(':memory:')
store.save_password password
store.save_secret primary_secret
store.save_secret secondary_secret
store.export_yaml yaml_fixture

$stdout.write <<~RUBY
  def primary_secret
    SecretStore::Secret.new('example', '#{primary_secret.iv}', '#{primary_secret.pbkdf2_salt}',
                            '#{primary_secret.crypted_text}', '#{primary_secret.auth_tag}')
  end

  def secondary_secret
    SecretStore::Secret.new('second', '#{secondary_secret.iv}', '#{secondary_secret.pbkdf2_salt}',
                            '#{secondary_secret.crypted_text}', '#{secondary_secret.auth_tag}')
  end
RUBY
