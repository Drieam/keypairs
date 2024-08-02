# frozen_string_literal: true

RSpec::Matchers.define :encrypt_attribute do |attribute|
  database_column_name = "#{attribute}_ciphertext"

  match do |model|
    # Correct responds to methods
    model.respond_to?(attribute) &&
      model.respond_to?(:"#{attribute}=") &&
      model.respond_to?(database_column_name) &&
      model.respond_to?(:"#{database_column_name}=") &&
      # Correct database columns
      model.class.column_names.exclude?(attribute.to_s) &&
      model.class.column_names.include?(database_column_name)
  end

  failure_message do |model|
    if model.class.column_names.include?(database_column_name)
      "#{attribute} should use lockbox encrypts on #{model.class}"
    else
      "#{database_column_name} must be a column on #{model.class} for encryption to work"
    end
  end

  failure_message_when_negated do |model|
    if model.class.column_names.include?(database_column_name)
      "#{attribute} should not use lockbox encrypts on #{model.class}"
    else
      "#{database_column_name} shouldn't be a column on #{model.class}"
    end
  end
end
