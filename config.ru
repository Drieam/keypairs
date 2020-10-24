# frozen_string_literal: true

require 'rubygems'
require 'bundler/setup'
require 'combustion'

Bundler.require(*Rails.groups)

Combustion.initialize! :active_record, :action_controller
run Combustion::Application
