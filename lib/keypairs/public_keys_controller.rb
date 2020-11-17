# frozen_string_literal: true

module Keypairs
  # Endpoint to fetch the current valid keypairs.
  #
  # @example
  #  {
  #    "keys": [
  #      {
  #        "kty": "RSA",
  #        "n": "wmi......1Gw",
  #        "e": "AQAB",
  #        "kid": "d8d1d4265d6c34acadce8a42fbbec167db1beaeb6ebbbf7fd555f6eb00bda76e",
  #        "alg": "RS256",
  #        "use": "sig"
  #      }
  #    ]
  #  }
  class PublicKeysController < ActionController::API
    def index
      # Always cache for 1 week, our rotation interval is much more than a week
      expires_in 1.week, public: true
      render json: Keypair.cached_keyset
    end
  end
end
