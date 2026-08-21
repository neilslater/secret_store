# frozen_string_literal: true

# Shared deterministic values from the checked-in compatibility fixtures.
module SecretStoreFixtures
  def example_password
    'QwertyUiop'
  end

  def example_bcrypt_salt
    '$2a$14$.WO3JtKxNhzlASL4eQpkEO'
  end

  def example_pbkdf_salt
    'rCLPwKKsFb5WwgY1y0LwAQ=='
  end

  def example_cipher
    '9_ZGG1_mabi9Q5qvxu4sOA== ~ k4TSdX28eTImvdDmzhtju-87-35msJBPilU_25JG6UE= ~ dKxORrEkMFsW_uAsr3fGHA=='
  end

  def example_checksum
    '3EG3i1.oq1T5cmZVlq.cnOt28gz6U8G'
  end

  def primary_plaintext
    'This is a secret!'
  end

  def secondary_plaintext
    'This is a second secret!'
  end

  def fixture_password
    SecretStore::Password.new(example_bcrypt_salt, example_pbkdf_salt, example_cipher)
  end

  def primary_secret
    SecretStore::Secret.new('example', 'u0CAnSPnSbN1sVi03_ck4A==', 'yLIp8f6eeIzxOEvA1-uzbw==',
                            'IWYGh4x98_4Flk_1OrhvaaI=', 'szbH9SG0pymGCpU3lkIWNA==')
  end

  def secondary_secret
    SecretStore::Secret.new('second', '_Ra_07_YwLgOlgFXxBh7Xg==', 'xTmbPzciYuTNa8MVIBzcVQ==',
                            'aLA1CoQz0beM8NrC_mAdtru_cmHod0Gv', 'WOLMoGcQdPl8hayLX9M4JQ==')
  end

  def sqlite_fixture
    File.expand_path('../fixture_store.dat', __dir__)
  end

  def yaml_fixture
    File.expand_path('../fixture_store.yml', __dir__)
  end

  def memory_store_fixture
    SecretStore::Store.import_yaml(yaml_fixture, ':memory:')
  end

  def secret_label
    'example'
  end

  def secret_iv
    'T21EPfxrJbLHJQvkB6mLXQ=='
  end

  def secret_pbkdf2_salt
    'fyKRMBY6hPpqXzj_XOjvQw=='
  end

  def secret_crypted_text
    'kDKTjtTYyvkLIGa2teBYzgc='
  end

  def secret_auth_tag
    'upzYf6VkGXMuS9ccAhTFPg=='
  end

  def serialized_secret_attributes
    { label: secret_label,
      iv: secret_iv,
      pbkdf2_salt: secret_pbkdf2_salt,
      crypted_text: secret_crypted_text,
      auth_tag: secret_auth_tag }
  end

  def secret_with_cipher(ciphertext)
    SecretStore::Secret.new(secret_label, secret_iv, secret_pbkdf2_salt, ciphertext, secret_auth_tag)
  end

  def flip_last_cipher_bit(encoded_ciphertext)
    decoded_ciphertext = Base64.urlsafe_decode64(encoded_ciphertext)
    decoded_ciphertext[-1] = (decoded_ciphertext[-1].ord ^ 4).chr
    Base64.urlsafe_encode64(decoded_ciphertext)
  end

  def changed_encryption_values(secret)
    keys = %i[iv pbkdf2_salt crypted_text auth_tag]
    current = secret.to_h.values_at(*keys)
    original = serialized_secret_attributes.values_at(*keys)
    current.zip(original)
  end

  def empty_yaml_store
    Tempfile.create('empty_secret_store.yml') do |yaml_file|
      yaml_file.write(YAML.dump({}))
      yaml_file.close
      return SecretStore::Store.import_yaml(yaml_file.path, ':memory:')
    end
  end

  def decrypted_texts(secrets)
    secrets.map { |secret| secret.decrypt_text(example_checksum) }
  end
end
