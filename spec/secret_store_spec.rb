# frozen_string_literal: true

require 'spec_helper'

describe SecretStore do
  it 'has a version number' do
    expect(SecretStore::VERSION).not_to be nil
  end
end
