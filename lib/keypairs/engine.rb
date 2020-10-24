# frozen_string_literal: true

module Keypairs
  # Rails engine for this gem.
  # It ensures that the migrations are automatically ran in the applications.
  class Engine < ::Rails::Engine
    initializer :append_migrations do |app|
      unless app.root.to_s.match? "#{root}/"
        config.paths['db/migrate'].expanded.each do |expanded_path|
          app.config.paths['db/migrate'] << expanded_path
        end
        # Apartment will modify this, but it doesn't fully support engine migrations,
        # so we'll reset it here
        ActiveRecord::Migrator.migrations_paths = app.paths['db/migrate'].to_a
      end
    end
  end
end
