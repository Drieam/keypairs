# frozen_string_literal: true

RSpec.describe Keypairs do
  it 'has a version number' do
    expect(described_class::VERSION).not_to be nil
  end

  it 'has an engine' do
    expect(described_class::Engine.engine_name).to eq 'keypairs'
  end
end
