# frozen_string_literal: true

RSpec.describe Keypairs::PublicKeysController, type: :request do
  context 'GET #index' do
    let!(:keypair1) { Keypair.create(created_at: 4.days.ago) }
    let!(:keypair2) { Keypair.create(created_at: 3.days.ago) }
    let!(:keypair3) { Keypair.create(created_at: 2.days.ago) }
    let!(:keypair4) { Keypair.create(created_at: 1.day.ago) }

    before { get '/jwks' }

    it 'renders the public exports of valid keys (the last three)' do
      expect(response.body).to eq({
        keys: [keypair4, keypair3, keypair2].map(&:public_jwk_export)
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
    # it 'sets the expiry headers' do
    #   get :index, format: :json
    #   expect(response.headers['Cache-Control']).to eq("max-age=#{1.week.to_i}, public")
    # end
  end
end
