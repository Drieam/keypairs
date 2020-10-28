# frozen_string_literal: true

require 'lockbox'

autoload :Keypair, 'keypair.rb'

module Keypairs
  autoload :PublicKeysController, 'keypairs/public_keys_controller'
end

require 'keypairs/engine' if defined?(Rails)
