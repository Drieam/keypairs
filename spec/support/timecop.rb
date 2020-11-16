# frozen_string_literal: true

require 'timecop'

RSpec.configure do |config|
  config.before(:each, :timecop) do |example|
    case example.metadata[:timecop].to_sym
    when :freeze then Timecop.freeze
    else raise NotImplementedError, 'This timecop helper only supports `:freeze`'
    end
  end

  config.after(:each, :timecop) do
    Timecop.return
  end
end
