# METADATA
# description: Helper library for JWT verification and decoding in Rego
# authors:
# - The Styra Community
# related_resources:
#   - description: JSON Web Token (JWT) specification
#     ref: https://www.rfc-editor.org/rfc/rfc7519
#   - description: JSON Web Signature (JWS) specification
#     ref: https://www.rfc-editor.org/rfc/rfc7515
#   - description: JSON Web Token Best Current Practices
#     ref: https://www.rfc-editor.org/rfc/rfc8725
package lib.jwt

import rego.v1

# METADATA
# description: |
#   All algorithms supported by OPA, in uppercase. Note that the symmetric
#   algorithms (HS256, HS384, HS512) is not supported by this library, as using them
#   is almost always a bad idea.
supported_algorithms := {
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384",
	"ES512",
	"PS256",
	"PS384",
	"PS512",
}

# METADATA
# description: |
#   - `allowed_issuers` — **must** contain at least one allowed issuer
#   - `time` — time to compare against `exp` if not current time should be used
decode_verify(jwt, config) := result if {
	# get verification key from conf, either via `key` or configured
	# metadata endpoint

	# regal ignore:with-outside-test-context
	result := _result with _config as object.union(config, {"jwt": jwt})
}

_config := {}

_decoded := io.jwt.decode(_config.jwt)

_headers := _decoded[0]

_claims := _decoded[1]

_errors contains "no signature verification keys provided" if not _keys_provided

_errors contains "signature verification failed" if not verify(_config.jwt, _config.jwks)

_errors contains "invalid token: header missing 'alg' value" if not _headers.alg

_errors contains sprintf("expected %s algorithm, got %s", [_config.alg, _headers.alg]) if _config.alg != _headers.alg

_errors contains sprintf("%s algorithm not supported", [_headers.alg]) if not _headers.alg in supported_algorithms

_errors contains "required 'allowed_issuers' missing from configuration" if not _config.allowed_issuers

_errors contains "'allowed_issuers' must contain at least one issuer" if count(_config.allowed_issuers) == 0

_errors contains sprintf("issuer %s not in list of allowed issuers", [_claims.iss]) if {
	not _claims.iss in _config.allowed_issuers
}

_keys_provided if {
	count(_config.jwks) > 0
}

_result["errors"] := _errors if count(_errors) > 0

_result["headers"] := _decoded[0] if count(_errors) == 0

_result["claims"] := _decoded[1] if count(_errors) == 0
