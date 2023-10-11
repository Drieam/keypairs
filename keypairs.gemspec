# frozen_string_literal: true

$LOAD_PATH.push File.expand_path('lib', __dir__)

# Maintain your gem's version:
require 'keypairs/version'

# Describe your gem and declare its dependencies:
Gem::Specification.new do |spec|
  spec.name        = 'keypairs'
  spec.version     = Keypairs::VERSION
  spec.authors     = ['Stef Schenkelaars']
  spec.email       = ['stef.schenkelaars@gmail.com']
  spec.homepage    = 'https://drieam.github.io/keypairs'
  spec.summary     = <<~MESSAGE
    Manage application level keypairs with automatic rotation and JWT support
  MESSAGE
  spec.description = spec.summary
  spec.license     = 'MIT'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.7.0')

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/Drieam/keypairs'

  spec.files = Dir['{app,db,lib}/**/*', 'LICENSE', 'README.md']

  spec.add_dependency 'actionpack', '>= 6.0', '< 8'                # Depend on actionpack to share public keys
  spec.add_dependency 'activerecord', '>= 6.0', '< 8'              # Depend on activerecord as ORM
  spec.add_dependency 'jwt', '~> 2.5'                              # Working with JSON Web Tokens
  spec.add_dependency 'lockbox', '~> 1.3'                          # Encrypt and decrypt attributes

  spec.add_development_dependency 'appraisal'                      # Test against multiple gem versions
  spec.add_development_dependency 'brakeman'                       # Static analysis security vulnerability scanner
  spec.add_development_dependency 'combustion'                     # Test rails engines
  spec.add_development_dependency 'database_cleaner-active_record' # Ensure clean state for testing
  spec.add_development_dependency 'rspec-github'                   # RSpec formatter for GitHub Actions
  spec.add_development_dependency 'rspec-rails'                    # Testing framework
  spec.add_development_dependency 'rubocop'                        # Linter
  spec.add_development_dependency 'rubocop-performance'            # Linter for Performance optimization analysis
  spec.add_development_dependency 'rubocop-rails'                  # Linter for Rails-specific analysis
  spec.add_development_dependency 'shoulda-matchers'               # RSpec matchers
  spec.add_development_dependency 'sqlite3'                        # Database adapter
  spec.add_development_dependency 'timecop'                        # Freeze time to test time-dependent code
end
