# frozen_string_literal: true

RSpec.describe Keypairs::PublicKeysController, type: :request do
  context 'GET #index' do
    let!(:keypair1) { Keypair.create(created_at: 14.weeks.ago) }
    let!(:keypair2) { Keypair.create(created_at: 10.weeks.ago) }
    let!(:keypair3) { Keypair.create(created_at: 6.weeks.ago) }
    let!(:keypair4) { Keypair.create(created_at: 2.weeks.ago) }
    let(:created_keypair) { Keypair.unscoped.last }

    before { get '/jwks' }

    it 'renders the public exports of valid keys' do
      expect(response.body).to eq({
        keys: [keypair3, keypair4, created_keypair].map(&:public_jwk_export)
      }.to_json)
    end

    # The Issuer MAY issue a cache-control: max-age HTTP header on
    # requests to retrieve a key set to signal how long the
    # retriever may cache the key set before refreshing it.
    #
    # See: https://www.imsglobal.org/spec/security/v1p0/#h_key-set-url
    #
    # You can enable this by adding `expires_in 1.week, public: true` to the controller action.
    #
    # NOTE: Be carefull with enabeling this, since if we rotate a key, it's not valid immediately!
    #
    it 'sets the expiry headers' do
      expect(response.headers['Cache-Control']).to eq("max-age=#{1.week.to_i}, public")
    end
  end
end
