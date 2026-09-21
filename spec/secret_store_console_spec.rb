# frozen_string_literal: true

require 'spec_helper'
require 'pp'

describe SecretStore do
  let(:password) { fixture_password }
  let(:store) { memory_store_fixture }
  let(:connection) { SecretStore::Connection.new(store, example_password) }

  after { store.db.close }

  it 'redacts inactive and active password formatting', :aggregate_failures do
    expect(password.inspect).to include('activated=false')
    password.activate_checksum(example_password)
    expect(password.inspect).to include('activated=true')
    expect(PP.pp([password], +'')).not_to include(example_checksum, example_password, example_cipher)
  end

  it 'redacts connection inspection and nested pretty printing', :aggregate_failures do
    expect(connection.inspect).to eq('#<SecretStore::Connection>')
    expect(PP.pp({ session: connection }, +'')).not_to include(example_checksum, example_password, example_cipher)
  end

  it 'does not inspect an invalid supplied store' do
    expect { SecretStore::Connection.new('PRIVATE-MARKER', example_password) }
      .to raise_error('Expected a SecretStore::Store')
  end

  it 'does not print invalid salt material' do
    expect { SecretStore::Password.new('PRIVATE-MARKER', example_pbkdf_salt, example_cipher) }
      .to raise_error(SecretStore::FormatError, 'Bad bcrypt_salt: expected a BCrypt salt')
  end

  context 'with the root executable' do
    let(:session) { ConsoleSession.new }
    let(:result) do
      session.run(steps: [['>', 'connect_secret_store'], ['Password:', example_password],
                          ['>', "read_secret 'example'"]])
    end

    it 'redacts reconnect output while allowing deliberate reads', :aggregate_failures do
      expect(result[1]).to be_success
      expect(result[0]).to include(primary_plaintext, '#<SecretStore::Connection>')
      expect(result[0]).not_to include(example_checksum, example_password)
    end

    it 'ignores RC files and does not write history after secret commands', :aggregate_failures do
      session.run(steps: [['>', "write_secret 'test', 'synthetic-secret'"]])
      expect(session.artifacts).to eq('rc-marker' => false, 'history' => false, 'wrong.dat' => false)
    end

    it 'honors spaced caller-relative arguments over the environment from another directory', :aggregate_failures do
      output, status = session.run(argument: true)
      expect(status).to be_success
      expect(output).to include('Connecting to fixture store.dat.')
      expect(session.artifacts['wrong.dat']).to be(false)
    end
  end
end
