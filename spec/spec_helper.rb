# frozen_string_literal: true

require 'simplecov'

SimpleCov.start do
  enable_coverage :branch
  minimum_coverage line: 95, branch: 95
  skip '/spec/'
end

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'secret_store'
require_relative 'support/console_session'
require_relative 'support/thread_barrier'
require_relative 'support/test_resources'
require_relative 'support/secret_store_fixtures'

RSpec.configure do |config|
  config.include TestResources
  config.include SecretStoreFixtures
  config.before { track_test_databases }
  config.after { release_test_resources }
end
