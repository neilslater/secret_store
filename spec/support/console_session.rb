# frozen_string_literal: true

require 'fileutils'
require 'pty'
require 'tempfile'
require 'timeout'

# Drives the root console with isolated fixture, RC, history, and working directory.
class ConsoleSession
  attr_reader :artifacts

  def initialize
    @output = +''
    @cursor = 0
  end

  def run(steps: [], argument: false)
    Dir.mktmpdir('secret store console') do |directory|
      @directory = directory
      create_files
      launch(steps, argument)
      @artifacts = %w[rc-marker history wrong.dat].to_h { |name| [name, File.exist?(path(name))] }
    end
    [@output, @process_status]
  rescue Timeout::Error
    raise 'Console did not exit within the test timeout'
  end

  private

  def path(name)
    File.join(@directory, name)
  end

  def create_files
    FileUtils.cp(File.expand_path('../fixture_store.dat', __dir__), path('fixture store.dat'))
    File.write(path('irbrc'), "File.write(#{path('rc-marker').inspect}, 'ran')\nIRB.conf[:SAVE_HISTORY] = 100\n")
  end

  def environment(argument)
    { 'IRB_USE_AUTOCOMPLETE' => 'false', 'NO_COLOR' => '1', 'TERM' => 'dumb',
      'IRBRC' => path('irbrc'), 'IRB_HISTORY' => path('history'), 'XDG_CONFIG_HOME' => @directory,
      'XDG_STATE_HOME' => @directory, 'SECRET_STORE_FILE' => path(argument ? 'wrong.dat' : 'fixture store.dat') }
  end

  def launch(steps, argument)
    executable = File.expand_path('../../console', __dir__)
    args = argument ? ['fixture store.dat'] : []
    PTY.spawn(environment(argument), executable, *args, chdir: @directory) do |reader, writer, process_id|
      interact(reader, writer, process_id, steps)
    ensure
      reap(process_id)
    end
  end

  def interact(reader, writer, process_id, steps)
    Timeout.timeout(20) do
      send_steps(reader, writer, [['Password:', 'QwertyUiop'], *steps])
      read_until(reader, '>')
      writer.puts 'exit'
      drain(reader)
      _, @process_status = Process.wait2(process_id)
    end
  end

  def send_steps(reader, writer, steps)
    steps.each do |prompt, input|
      read_until(reader, prompt)
      writer.puts(input)
    end
  end

  def read_until(reader, text)
    @output << reader.readpartial(1024) until (position = @output.index(text, @cursor))
    @cursor = position + text.length
  end

  def drain(reader)
    @output << reader.readpartial(1024) until reader.eof?
  rescue Errno::EIO
    # Some PTYs report EIO when the child closes the terminal.
  end

  def reap(process_id)
    return if @process_status

    Process.kill('KILL', process_id)
    Process.waitpid(process_id)
  rescue Errno::ESRCH, Errno::ECHILD
    # The PTY implementation may already have reaped an exited child.
  end
end
