# frozen_string_literal: true

# Owns real database handles and temporary fixture copies for each example.
module TestResources
  def test_directory
    @test_directory ||= Dir.mktmpdir('secret-store-spec')
  end

  def test_databases
    @test_databases ||= []
  end

  def track_test_databases
    allow(SQLite3::Database).to receive(:new).and_wrap_original do |original, *args, **options|
      original.call(*args, **options).tap { |database| test_databases << database }
    end
  end

  def release_test_resources
    test_databases.reverse_each { |database| database.close unless database.closed? }
  ensure
    FileUtils.remove_entry(@test_directory) if @test_directory
  end
end
