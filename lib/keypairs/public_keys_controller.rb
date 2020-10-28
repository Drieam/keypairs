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
      render json: Keypair.keyset
    end
  end
end
