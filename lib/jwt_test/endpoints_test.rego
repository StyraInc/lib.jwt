package lib.jwt_test

import rego.v1

import data.lib.jwt

test_only_one_jwks_provider_allowed if {
	# regal ignore:line-length
	expected := "only one of jwks, endpoints.jwks_uri, endpoints.use_oidc_metadata or endpoints.use_oauth2_metadata can be set"

	expected in jwt.errors with jwt._config as {
		"jwks": {"keys": []},
		"endpoints": {"use_oauth2_metadata": true},
	}
}

test_jwks_from_jwks_uri if {
	token := io.jwt.encode_sign(
		{"alg": "RS256"},
		{"iss": "https://foo.bar"},
		rsa_private,
	)

	jwks := jwt._jwks with jwt._config as {
		"allowed_issuers": ["https://foo.bar"],
		"endpoints": {"jwks_uri": "https://foo.bar/jwks"},
		"jwt": token,
	}
		with http.send as mock_http_send

	jwks == jwks_keys
}

test_jwks_from_oidc_metadata if {
	token := io.jwt.encode_sign(
		{"alg": "RS256"},
		{"iss": "https://foo.bar"},
		rsa_private,
	)

	jwks := jwt._jwks with jwt._config as {
		"allowed_issuers": ["https://foo.bar"],
		"endpoints": {"use_oidc_metadata": true},
		"jwt": token,
	}
		with http.send as mock_http_send

	jwks == jwks_keys
}

test_jwks_from_oauth2_metadata if {
	token := io.jwt.encode_sign(
		{"alg": "RS256"},
		{"iss": "https://foo.bar"},
		rsa_private,
	)

	jwks := jwt._jwks with jwt._config as {
		"allowed_issuers": ["https://foo.bar"],
		"endpoints": {"use_oauth2_metadata": true},
		"jwt": token,
	}
		with http.send as mock_http_send

	jwks == jwks_keys
}

test_complete_decode_verify_flow_using_oidc_metadata if {
	token := io.jwt.encode_sign(
		{"alg": "RS256"},
		{
			"iss": "https://foo.bar",
			"exp": jwt.nanos_to_seconds(time.now_ns()) + 10,
		},
		rsa_private,
	)

	result := jwt.decode_verify(token, {
		"allowed_issuers": ["https://foo.bar"],
		"endpoints": {"use_oidc_metadata": true},
		"jwt": token,
	}) with http.send as mock_http_send

	not result.errors
}

mock_http_send({
	"url": "https://foo.bar/.well-known/openid-configuration",
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 3600,
	"raise_error": false,
}) := {
	"status_code": 200,
	"body": {"jwks_uri": "https://foo.bar/jwks"},
}

mock_http_send({
	"url": "https://foo.bar/.well-known/oauth-authorization-server",
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 3600,
	"raise_error": false,
}) := {
	"status_code": 200,
	"body": {"jwks_uri": "https://foo.bar/jwks"},
}

mock_http_send({
	"url": "https://foo.bar/jwks",
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 3600,
	"raise_error": false,
}) := {
	"status_code": 200,
	"body": jwks_keys,
}

jwks_keys := {"keys": [{
	"kty": "RSA",
	"n": "muU3VcHLEcZqAvpkrV36oS0pPUhH8-qOumoF2JSx2l8FvkzA4m-9cFFj72qBMg1_DHeuZNMBmn3cT_wjyNl7P49jt8G6kD32uuouK2rKhPJpx2KvGC5moR5_6IbQ87S6C1WxHzuAzdbbxRFimeZUBsnM1mb2rxYJLDTsl39e0GE69eP4nfof6aJl2j6duRHtPDeDFJUgtwE3-NnKcKUzdgFxO8n4QefbOCiNrDjaganMYM4leUpnPGKpAAfsH0yjZp_tmrLFDZRzjW5iZzkY9vw6kn8O0QVZZ3-hMADJsl8sRPtkJb-sQ4bDWSr0uKwuO0SJzlxh0H7OSQdPGA18rw",
	"e": "AQAB",
}]}
