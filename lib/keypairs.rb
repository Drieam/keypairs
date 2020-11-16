# frozen_string_literal: true

require 'lockbox'

autoload :Keypair, 'keypair.rb'

# The Keypairs module contains common functionality in support of the {Keypair} model.
module Keypairs
  autoload :PublicKeysController, 'keypairs/public_keys_controller'
end

require 'keypairs/engine' if defined?(Rails)
