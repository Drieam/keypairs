# frozen_string_literal: true

require 'attr_encrypted'
require 'jwt'

# This class contains functionality needed for signing messages
# and publishing JWK[s].
#
# The last three created keypairs are considered valid, so creating a new Keypair
# will invalidate the second to last created Keypair.
#
# If you need to sign messages, use the {Keypair.current} keypair for this. This method
# performs the rotation of the keypairs if required.
#
# You can also use the +jwt_encode+ and +jwt_decode+ methods directly to encode and
# securely decode your payloads
#
# @example
#   payload = { foo: 'bar' }
#   id_token = Keypair.jwt_encode(payload)
#   decoded = Keypair.jwt_decode(id_token)
#
# @attr [String] jwk_kid The public external id of the key used to find the associated key on decoding.
class Keypair < ActiveRecord::Base
  ALGORITHM = 'RS256'

  attr_encrypted :_keypair, key: Rails.application.secrets.secret_key_base[0, 32]

  validates :_keypair, presence: true
  validates :jwk_kid, presence: true

  after_initialize :set_keypair

  # @!method valid
  #   @!scope class
  #   The last 3 keypairs are considered valid and can be used to validate signatures and export public jwks.
  #   It uses a subquery to make sure a +find_by+ actually searches only the valid 3 ones.
  scope :valid, -> { where(id: unscoped.order(created_at: :desc).limit(3)) }

  # @return [Keypair] the keypair used to sign messages and autorotates if it is older than 1 month.
  def self.current
    order(:created_at).where(arel_table[:created_at].gt(1.month.ago)).last || create!
  end

  # The JWK Set of our valid keypairs.
  # @return [Hash]
  # @example
  #   {
  #     keys: [{
  #       e: "AQAB",
  #       use: "sig",
  #       alg: "RS256",
  #       kty: "RSA",
  #       n: "oNqXxxWuX7LlovO5reRNauF6TEFa-RRRl8Dw==...",
  #       kid: "1516918956_0"
  #     }, {
  #       e: "AQAB",
  #       use: "sig",
  #       alg: "RS256",
  #       kty: "RSA",
  #       n: "kMfHwTp2dIYybtvU-xzF2E3dRJBNm6g5kTQi8itw==...",
  #       kid: "1516918956_1"
  #     }]
  #   }
  #
  # @see https://www.imsglobal.org/spec/security/v1p0/#h_key-set-url
  def self.keyset
    {
      keys: valid.order(created_at: :desc).map(&:public_jwk_export)
    }
  end

  # Encodes the payload with the current keypair.
  # It forewards the call to the instance method {Keypair#jwt_encode}.
  # @return [String] Encoded JWT token with security credentials.
  # @param payload [Hash] Hash which should be encoded.
  def self.jwt_encode(payload)
    current.jwt_encode(payload)
  end

  # Decodes the payload and verifies the signature against the current valid keypairs.
  # @param id_token [String] A JWT that should be decoded.
  # @param options [Hash] options for decoding, passed to {JWT::Decode}.
  # @raise [JWT::DecodeError] or any of it's subclasses if the decoding / validation fails.
  # @return [Hash] Decoded payload hash with indifferent access.
  def self.jwt_decode(id_token, options = {})
    # Add default decoding options
    options.reverse_merge!(
      # Change the default algorithm to match the encoding algorithm
      algorithm: ALGORITHM,
      # Load our own keyset as valid keys
      jwks: keyset,
      # If the `sub` is provided, validate that it matches the payload `sub`
      verify_sub: true
    )
    JWT.decode(id_token, nil, true, options).first.with_indifferent_access
  end

  # JWT encodes the payload with this keypair.
  # It automatically adds the security attributes +iat+, +exp+ and +nonce+ to the payload.
  # It automatically sets the +kid+ in the header.
  # @param payload [Hash] you have to provide a hash since the security attributes have to be added.
  # @param headers [Hash] you can optionally add additional headers to the JWT.
  def jwt_encode(payload, headers = {})
    # Add security claims to payload
    payload.reverse_merge!(
      # Time at which the Issuer generated the JWT (epoch).
      iat: Time.now.to_i,

      # Expiration time on or after which the tool MUST NOT accept the ID Token for
      # processing (epoch). This is mostly used to allow some clock skew.
      exp: Time.now.to_i + 5.minutes.to_i,

      # String value used to associate a tool session with an ID Token, and to mitigate replay
      # attacks. The nonce value is a case-sensitive string.
      nonce: SecureRandom.uuid
    )

    # Add additional info into the headers
    headers.reverse_merge!(
      # Set the id of they key
      kid: jwk_kid
    )

    JWT.encode(payload, private_key, ALGORITHM, headers)
  end

  # Public representation of the keypair in the JWK format.
  # We append the +alg+, and +use+ parameters to our JWK to indicate
  # that our intended use is to generate signatures using +RS256+.
  #
  # +alg+::
  #   This (algorithm) parameter identifies the algorithm intended for use with the key.
  #   It is based in the {Keypair::ALGORITHM}.
  #   The IMS Security framework specifies that the +alg+ value SHOULD be the default of +RS256+.
  #   Use of this member is OPTIONAL.
  # +use+::
  #   This (public key use) parameter identifies the intended use of the public key.
  #   Use of this member is OPTIONAL, unless the application requires its presence.
  #
  # @see https://tools.ietf.org/html/rfc7517#section-4.4
  # @see https://www.imsglobal.org/spec/security/v1p0#authentication-response-validation
  def public_jwk_export
    public_jwk.export.merge(
      alg: ALGORITHM,
      use: 'sig'
    )
  end

  # @return [OpenSSL::PKey::RSA] {OpenSSL::PKey::RSA} instance loaded with our keypair.
  def private_key
    OpenSSL::PKey::RSA.new(_keypair)
  end

  # @return [OpenSSL::PKey::RSA] {OpenSSL::PKey::RSA} instance loaded with the public part our keypair.
  delegate :public_key, to: :private_key

  private

  # @return [JWT::JWK] {JWT::JWK} instance with the public part of our keypair.
  def public_jwk
    JWT::JWK.create_from(public_key)
  end

  # Generate a new keypair with a key_size of 2048. Keys less than 1024 bits should be
  # considered insecure.
  #
  # See:
  # https://ruby-doc.org/stdlib-2.6.5/libdoc/openssl/rdoc/OpenSSL/PKey/RSA.html#method-c-new
  def set_keypair
    # The generated keypair is stored in PEM encoding.
    self._keypair ||= OpenSSL::PKey::RSA.new(2048).to_pem
    self.jwk_kid = public_jwk.kid
  end
end
