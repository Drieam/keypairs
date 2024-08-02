# frozen_string_literal: true

# Based on https://stackoverflow.com/a/13423584
RSpec::Matchers.define :exceed_query_limit do |expected|
  match do |block|
    query_count(&block) > expected
  end

  failure_message_when_negated do |_actual|
    queries = @queries.map do |query|
      if query[:location]
        <<~TEXT
          #{query[:name]}: #{query[:sql]}
            ↳ #{query[:location]}
        TEXT
      else
        <<~TEXT
          #{query[:name]}: #{query[:sql]}
        TEXT
      end
    end.join.indent(4)

    <<~TEXT
      Expected to run maximum #{expected} queries, got #{@query_count}:
      #{queries}
    TEXT
  end

  def query_count(&block)
    @query_count = 0
    @queries = []
    ActiveSupport::Notifications.subscribed(method(:query_callback), 'sql.active_record', &block)
    @query_count
  end

  def query_callback(_name, _start, _finish, _message_id, values)
    return if %w[CACHE SCHEMA].include?(values[:name])

    @query_count += 1
    @queries << { sql: values[:sql], name: values[:name], location: Rails.backtrace_cleaner.clean(caller).first }
  end

  def supports_block_expectations?
    true
  end
end
