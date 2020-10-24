# Keypairs
Applications often need to have a public/private keypair so sign messages. This gem manages your application level key pairs with automatic rotation and support for encoding and decoding [JWTs](https://jwt.io/).

Note: This gem is intended to work within Rails applications. It can probably be adjusted easily to also work for non-rails / sinatra project but that's out of scope for now. 

## Installation
Add this line to your application's Gemfile:

```ruby
gem 'keypairs'
```

The of course run `bundle install` and run the migrations `bundle exec rake db:migrate`. The migrations from the gem run automatically.

## Usage
The central point of this gem is the `Keypair` model which is backed by the `keypairs` table. If you need to sign messages, you can get the current keypair with the `Keypair.current` method. This method performs the rotation of the keypairs if required.

You can access the private an public key of the keypair (`OpenSSL::PKey::RSA`) and encrypt and decrypt messages with them:

```ruby
encoded_message = Keypair.current.private_key.private_decrypt('foobar')
Keypair.current.public_key.public_decrypt(encoded_message)
# => 'foobar'
```

### JWT support
You can encode and decode JWTs directly on the class:
```ruby 
payload = { foo: 'bar' }
id_token = Keypair.jwt_encode(payload)
decoded = Keypair.jwt_decode(id_token)
```

It's almost always a good idea to add a subject to your payload and pass the same subject during decoding. That way you know that users don't use a key for other purposes (for example a key intended for an OAuth2 flow used as a session key). So for example:

```ruby
subject = 'MyAppSession'
payload = { foo: 'bar', subject: subject }
id_token = Keypair.jwt_encode(payload)
decoded = Keypair.jwt_decode(id_token, subject: subject)
``` 

### Exposing public keys
If you want others to validate your messages based on the public keys, you can share the JWK version of you current keys by adding them to your `config/routes.rb`:

```ruby
get :jwks, to: Keypairs::PublicKeysController.action(:index)
```

## Releasing new version
Publishing a new version is handled by the publish workflow. This workflow publishes a GitHub release to rubygems and GitHub package registry with the version defined in the release.

## Contributing
Bug reports and pull requests are welcome on GitHub at https://github.com/Drieam/keypairs.

## License
The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
