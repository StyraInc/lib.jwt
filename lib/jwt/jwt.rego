# METADATA
# description: Helper library for JWT verification and decoding in Rego
# entrypoint: true
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
#   algorithms (HS256, HS384, HS512) are not supported by this library, as using them
#   for anything but development/testing is almost always a bad idea.
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

_input_path_jwt := _clean_path(arr) if {
	is_string(data.lib.config.jwt.input_path_jwt)

	path := trim_space(trim_prefix(trim_prefix(data.lib.config.jwt.input_path_jwt, "Bearer"), "bearer"))
	arr := split(path, ".")
}

_input_path_jwt := _clean_path(data.lib.config.jwt.input_path_jwt) if is_array(data.lib.config.jwt.input_path_jwt)

_clean_path(arr) := arr if not arr[0] == "input"

_clean_path(arr) := array.slice(arr, 1, count(arr)) if arr[0] == "input"

# METADATA
# description: the claims of the verified JWT, from calling `decode_verify` direct
claims := _result.claims

# METADATA
# description: the claims of the verified JWT, from config-based verification
claims := _verified.claims

# METADATA
# description: the header of the verified JWT, from calling `decode_verify` direct
header := _result.header

# METADATA
# description: the header of the verified JWT, from config-based verification
header := _verified.header

# METADATA
# description: errors encountered while processing the JWT, from calling `decode_verify` direct
errors := _result.errors

# METADATA
# description: the header of the verified JWT, from config-based verification
errors := _verified.errors

_config := {}

_decoded := io.jwt.decode(_config.jwt)

_headers := _decoded[0]

_claims := _decoded[1]

_errors contains "no signature verification keys provided" if not _keys_provided

_errors contains "signature verification failed" if not verify(_config.jwt, _config)

_errors contains "invalid token: header missing 'alg' value" if not _headers.alg

_errors contains sprintf("expected %s algorithm, got %s", [_config.alg, _headers.alg]) if _config.alg != _headers.alg

_errors contains sprintf("%s algorithm not supported", [_headers.alg]) if not _headers.alg in supported_algorithms

_errors contains "required 'allowed_issuers' missing from configuration" if not _config.allowed_issuers

_errors contains "'allowed_issuers' must contain at least one issuer" if count(_config.allowed_issuers) == 0

_errors contains sprintf("issuer %s not in list of allowed issuers", [_claims.iss]) if {
	not _claims.iss in _config.allowed_issuers
}

_keys_provided if count(_config.jwks) > 0

_verified := decode_verify(input_from_config, data.lib.config.jwt) if {
	input_from_config := object.get(input, _input_path_jwt, null)
	input_from_config != null
}

_result["errors"] := _errors if count(_errors) > 0

_result["headers"] := _decoded[0] if count(_errors) == 0

_result["claims"] := _decoded[1] if count(_errors) == 0
