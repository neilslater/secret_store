# frozen_string_literal: true

# Coordinates SQLite handles without timing sleeps and always joins the worker.
class ThreadBarrier
  def initialize
    @entered = Queue.new
    @release = Queue.new
  end

  def pause
    @entered << true
    @release.pop
  end

  def run(operation)
    worker = Thread.new(&operation)
    Timeout.timeout(15) do
      @entered.pop
      yield
    end
  ensure
    @release << true
    worker&.value
  end
end
