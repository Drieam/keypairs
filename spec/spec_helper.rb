# frozen_string_literal: true

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

Lockbox.master_key = Lockbox.generate_key

RSpec.configure do |config|
  config.use_transactional_fixtures = true

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
