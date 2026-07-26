# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'pty'
require 'tempfile'
require 'timeout'

# rubocop:disable RSpec/DescribeClass
describe 'console' do
  # rubocop:disable RSpec/ExampleLength
  it 'exits cleanly from an empty session' do
    store = Tempfile.new(['secret_store_console', '.dat'])
    store.close
    FileUtils.cp(File.expand_path('fixture_store.dat', __dir__), store.path)

    output = +''
    process_status = nil
    environment = { 'IRB_USE_AUTOCOMPLETE' => 'false',
                    'NO_COLOR' => '1',
                    'SECRET_STORE_FILE' => store.path,
                    'TERM' => 'dumb' }
    PTY.spawn(environment, File.expand_path('../console', __dir__)) do |reader, writer, process_id|
      Timeout.timeout(15) do
        output << reader.readpartial(1024) until output.include?('Password:')
        writer.puts 'QwertyUiop'
        output << reader.readpartial(1024) until output.include?('secret_store(main):001>')
        writer.puts 'exit'
        writer.close
        begin
          output << reader.readpartial(1024) until reader.eof?
        rescue Errno::EIO
          # PTY raises EIO on macOS when the child closes the terminal.
        end
        _, process_status = Process.wait2(process_id)
      end
    rescue Timeout::Error
      raise "Console did not exit. Output: #{output.inspect}"
    end

    expect(process_status).to be_success
    expect(output).not_to include('NameError')
  ensure
    store&.unlink
  end
  # rubocop:enable RSpec/ExampleLength
end
# rubocop:enable RSpec/DescribeClass
