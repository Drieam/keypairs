# frozen_string_literal: true

# require "bundler/setup"
# require "keypair"
#
# RSpec.configure do |config|
#   # Enable flags like --only-failures and --next-failure
#   config.example_status_persistence_file_path = ".rspec_status"
#

# end

ENV['RAILS_ENV'] ||= 'test'

require 'bundler/setup'
require 'combustion'

Bundler.require(*Rails.groups)

# Load the parts from rails we need with combustion
Combustion.initialize! :active_record, :action_controller

require 'rspec/rails'

# Load support files
Dir[File.join(File.dirname(__FILE__), 'support', '**', '*.rb')].sort.each { |f| require f }

require 'keypairs'

RSpec.configure do |config|
  config.use_transactional_fixtures = true

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
