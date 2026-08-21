# frozen_string_literal: true

require 'fileutils'
require 'pty'
require 'tempfile'
require 'timeout'

# Drives the console executable through a pseudoterminal for integration tests.
class ConsoleSession
  def initialize
    @output = +''
  end

  def run
    create_store
    PTY.spawn(environment, console_path) do |reader, writer, process_id|
      interact(reader, writer, process_id)
    end
    [@output, @process_status]
  rescue Timeout::Error
    raise "Console did not exit. Output: #{@output.inspect}"
  ensure
    @store&.unlink
  end

  private

  def create_store
    @store = Tempfile.new(['secret_store_console', '.dat'])
    @store.close
    FileUtils.cp(File.expand_path('../fixture_store.dat', __dir__), @store.path)
  end

  def environment
    { 'IRB_USE_AUTOCOMPLETE' => 'false',
      'NO_COLOR' => '1',
      'SECRET_STORE_FILE' => @store.path,
      'TERM' => 'dumb' }
  end

  def console_path
    File.expand_path('../../console', __dir__)
  end

  def interact(reader, writer, process_id)
    Timeout.timeout(15) do
      read_until(reader, 'Password:')
      writer.puts 'QwertyUiop'
      read_until(reader, 'secret_store(main):001>')
      writer.puts 'exit'
      writer.close
      drain(reader)
      _, @process_status = Process.wait2(process_id)
    end
  end

  def read_until(reader, text)
    @output << reader.readpartial(1024) until @output.include?(text)
  end

  def drain(reader)
    @output << reader.readpartial(1024) until reader.eof?
  rescue Errno::EIO
    # PTY raises EIO on macOS when the child closes the terminal.
  end
end
