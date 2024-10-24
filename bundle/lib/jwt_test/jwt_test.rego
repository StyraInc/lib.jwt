package lib.jwt_test

import rego.v1

import data.lib.jwt

test_decode_verify_bad_key if {
	token := rsa_token({"alg": "RS256"}, {})

	result := jwt.decode_verify(token, {"jwks": {"keys": []}, "allowed_issuers": ["https://foo.bar.com"]})

	result.errors == {"signature verification failed"}
}

test_decode_verify_good_key_bad_alg if {
	token := rsa_token({"alg": "RS256"}, {})

	result := jwt.decode_verify(token, {
		"jwks": {"keys": {"keys": [rsa_public]}},
		"alg": "ES512",
		"allowed_issuers": ["https://foo.bar.com"],
	})

	"signature verification failed" in result.errors
	"expected ES512 algorithm, got RS256" in result.errors
}

test_decode_verify_missing_allowed_issuers if {
	token := rsa_token({"alg": "RS256"}, {"iss": "https://foo.bar"})

	result := jwt.decode_verify(token, {
		"jwks": {"keys": [rsa_public]},
		"alg": "ES512",
	})

	"required 'allowed_issuers' missing from configuration" in result.errors
}

test_decode_verify_missing_alg_header if {
	token := sprintf("%s.%s.", [
		base64url.encode_no_pad(`{"typ": "JWT"}`),
		base64url.encode_no_pad(`{"iss": "https://foo.bar.com"}`),
	])

	result := jwt.decode_verify(token, {
		"jwks": {"keys": [rsa_public]},
		"alg": "RS256",
		"allowed_issuers": ["https://foo.bar.com"],
	})

	"invalid token: header missing 'alg' value" in result.errors
}

test_decode_verify_unsupported_algorithm if {
	token := io.jwt.encode_sign({"alg": "HS512"}, {}, {
		"kty": "oct",
		"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
	})

	result := jwt.decode_verify(token, {
		"jwks": {"keys": [rsa_public]},
		"alg": "RS256",
		"allowed_issuers": ["https://foo.bar.com"],
	})

	"HS512 algorithm not supported" in result.errors
}

rsa_token(headers, claims) := io.jwt.encode_sign(headers, claims, {"keys": [rsa_private]})
