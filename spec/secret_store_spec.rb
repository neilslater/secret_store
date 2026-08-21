# frozen_string_literal: true

require 'spec_helper'

describe SecretStore do
  subject(:console) { Object.new.extend(described_class) }

  let(:connection) { instance_spy(SecretStore::Connection) }
  let(:store) { instance_spy(SecretStore::Store) }

  it 'has a version number' do
    expect(SecretStore::VERSION).not_to be_nil
  end

  context 'when running the console executable' do
    it 'exits cleanly from an empty session', :aggregate_failures do
      output, process_status = ConsoleSession.new.run
      expect(process_status).to be_success
      expect(output).not_to include('NameError')
    end
  end

  describe 'console helpers' do
    before do
      allow($stdin).to receive(:noecho).and_return("QwertyUiop\n")
      allow(SecretStore::Connection).to receive(:load).and_return(connection)
    end

    describe '#default_secrets_file' do
      it 'uses the configured file' do
        allow(ENV).to receive(:[]).with('SECRET_STORE_FILE').and_return('/configured/secrets.dat')

        expect(console.default_secrets_file).to eq '/configured/secrets.dat'
      end

      it 'defaults to a file in the home directory' do
        allow(ENV).to receive(:[]).with('SECRET_STORE_FILE').and_return(nil)
        allow(Dir).to receive(:home).and_return('/home/example')

        expect(console.default_secrets_file).to eq '/home/example/secrets.sqlite3.dat'
      end
    end

    describe '#default_backup_file' do
      it 'uses the configured file' do
        allow(ENV).to receive(:[]).with('SECRET_EXPORT_FILE').and_return('/configured/secrets.yml')

        expect(console.default_backup_file).to eq '/configured/secrets.yml'
      end

      it 'defaults to a file in the home directory' do
        allow(ENV).to receive(:[]).with('SECRET_EXPORT_FILE').and_return(nil)
        allow(Dir).to receive(:home).and_return('/home/example')

        expect(console.default_backup_file).to eq '/home/example/secrets_export.yml'
      end
    end

    describe '#connect_secret_store' do
      it 'loads the store using the entered password', :aggregate_failures do
        expect(console.connect_secret_store('/tmp/secrets.dat')).to eq connection
        expect(SecretStore::Connection).to have_received(:load).with('/tmp/secrets.dat', 'QwertyUiop')
      end
    end

    describe 'connected operations' do
      before do
        allow(connection).to receive(:store).and_return(store)
        console.connect_secret_store('/tmp/secrets.dat')
      end

      it 'exports secrets and returns the export filename', :aggregate_failures do
        expect(console.export_secrets('/tmp/export.yml')).to eq '/tmp/export.yml'
        expect(store).to have_received(:export_yaml).with('/tmp/export.yml')
      end

      it 'writes secrets using string labels', :aggregate_failures do
        expect(console.write_secret(123, 'content')).to be_nil
        expect(connection).to have_received(:write_secret).with('123', 'content')
      end

      it 'reads secrets using string labels', :aggregate_failures do
        allow(connection).to receive(:read_secret).with('123').and_return('content')

        expect(console.read_secret(123)).to eq 'content'
        expect(connection).to have_received(:read_secret).with('123')
      end

      it 'deletes secrets using string labels', :aggregate_failures do
        expect(console.delete_secret(123)).to be_nil
        expect(connection).to have_received(:delete_secret).with('123')
      end

      it 'lists secret labels' do
        allow(connection).to receive(:all_secret_labels).and_return(%w[first second])

        expect(console.all_secret_labels).to eq %w[first second]
      end
    end

    describe '#change_password' do
      before do
        console.connect_secret_store('/tmp/secrets.dat')
      end

      it 'changes the connection password when entries match', :aggregate_failures do
        allow($stdin).to receive(:noecho).and_return("new-password\n")

        expect(console.change_password).to be_nil
        expect(connection).to have_received(:change_password).with('new-password')
      end

      it 'rejects mismatched entries' do
        allow($stdin).to receive(:noecho).and_return("new-password\n", "different-password\n")

        expect { console.change_password }.to raise_error RuntimeError, /do not match/
      end
    end

    describe '#help!' do
      it 'prints the available console operations' do
        expect { console.help! }.to output(/read_secret.*write_secret.*export_secrets/m).to_stdout
      end
    end
  end
end
