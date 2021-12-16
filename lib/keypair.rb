# frozen_string_literal: true

require 'lockbox'
require 'jwt'

# This class contains functionality needed for signing messages
# and publishing JWK[s].
#
# Keypairs are considered valid based on their {#not_before}, {#not_after} and {#expires_at} attributes.
#
# A keypair can be used for signing if:
# - The current time is greater than or equal to {#not_before}
# - The current time is less than or equal to {#not_after}
#
# A keypair can be used for validation if:
# - The current time is less than {#expires_at}.
#
# By default, this means that when a key is created, it can be used for signing for 1 month and can still be used
# for signature validation 1 month after it is not used for signing (i.e. for 2 months since it started being used
# for signing).
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
# @attr [Time] not_before The time before which no payloads may be signed using the keypair.
# @attr [Time] not_after The time after which no payloads may be signed using the keypair.
# @attr [Time] expires_at The time after which the keypair may not be used for signature validation.
class Keypair < ActiveRecord::Base
  ALGORITHM = 'RS256'
  ROTATION_INTERVAL = 1.month

  lockbox_encrypts :_keypair

  validates :_keypair, presence: true
  validates :jwk_kid, presence: true
  validates :not_before, :expires_at, presence: true

  validate :not_after_after_not_before
  validate :expires_at_after_not_after

  after_initialize :set_keypair
  after_initialize :set_validity

  # @!method valid
  #   @!scope class
  #   Non-expired keypairs are considered valid and can be used to validate signatures and export public jwks.
  scope :valid, -> { where(arel_table[:expires_at].gt(Time.zone.now)) }

  # @return [Keypair] the keypair used to sign messages and autorotates if it has expired.
  def self.current
    order(not_before: :asc)
      .where(arel_table[:not_before].lteq(Time.zone.now))
      .where(arel_table[:not_after].gteq(Time.zone.now))
      .last || create!
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
    valid_keys = valid.order(not_before: :asc).to_a
    # If we don't have any keys or if we don't have a future key (i.e. the last key is the current key)
    while valid_keys.last.nil? || valid_keys.last.not_before <= Time.zone.now
      # There is an automatic fallback to Time.zone.now if not_before is not set
      valid_keys << create!(not_before: valid_keys.last&.not_after)
    end

    {
      keys: valid_keys.map(&:public_jwk_export)
    }
  end

  # @return [Hash] a cached version of the keyset
  # @see #keyset
  def self.cached_keyset
    Rails.cache.fetch('keypairs/Keypair/keyset', expires_in: 12.hours) do
      keyset
    end
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

  # Set the validity timestamps based on the rotation interval.
  def set_validity
    self.not_before ||= created_at || Time.zone.now
    self.not_after ||= not_before + ROTATION_INTERVAL
    self.expires_at ||= not_after + ROTATION_INTERVAL
  end

  def not_after_after_not_before
    return if not_before.nil? || not_after.nil?
    return if not_after > not_before

    errors.add(:not_after, 'must be after not before')
  end

  def expires_at_after_not_after
    return if not_after.nil? || expires_at.nil?
    return if expires_at > not_after

    errors.add(:expires_at, 'must be after not after')
  end
end
