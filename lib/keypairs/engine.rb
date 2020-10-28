# frozen_string_literal: true

module Keypairs
  # This engine is only needed to add the migration installation rake task.
  class Engine < ::Rails::Engine
    engine_name 'keypairs'
  end
end
