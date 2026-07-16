# frozen_string_literal: true

# Gem manifest for the N-PAMP (draft-bubblefish-npamp-01) OPEN reference library, Ruby port.
# Makes impl/ruby a consumable, publishable RubyGems package: `gem` "npamp". Pure Ruby on the
# standard library (crypto from stdlib `openssl`); no runtime gem dependencies. `gem build
# npamp.gemspec` produces the publishable .gem; `gem push` is credential-gated in
# .github/workflows/publish.yml (blocked until the operator supplies the RubyGems API key).

Gem::Specification.new do |spec|
  spec.name        = "npamp"
  spec.version     = "0.1.0"
  spec.summary     = "N-PAMP (draft-bubblefish-npamp-01) OPEN wire-format reference library."
  spec.description = "Open reference implementation of N-PAMP (draft-bubblefish-npamp-01) wire " \
                     "format: frame codec, AES-256-GCM record layer, HKDF-Expand-Label key " \
                     "schedule, and handshake-binding primitives (Standard profile). Pure Ruby " \
                     "on the standard library; no runtime gem dependencies."
  spec.authors     = ["BubbleFish Technologies, Inc."]
  spec.license     = "Apache-2.0"
  spec.homepage    = "https://github.com/bubblefish-tech/npamp_protocol"

  # Ed25519 via stdlib OpenSSL and modern syntax are relied on; verified against Ruby 4.0.5
  # (QUICKSTART.md). 3.1 is the conservative floor.
  spec.required_ruby_version = ">= 3.1"

  spec.metadata = {
    "source_code_uri"       => "https://github.com/bubblefish-tech/npamp_protocol",
    "bug_tracker_uri"       => "https://github.com/bubblefish-tech/npamp_protocol/issues",
    "rubygems_mfa_required" => "true"
  }

  # Ship the library sources + the quickstart; the pinned test vectors and KATs are graded by
  # the cross-language conformance harness, not carried in the consumer gem.
  spec.files       = Dir["lib/**/*.rb"] + ["QUICKSTART.md"]
  spec.require_paths = ["lib"]
end
