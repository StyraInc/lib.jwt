package libraries.jwt

import rego.v1

# deleteme

_jwks := _jwks_response.body if {
	_jwks_response.status_code == 200
}

_jwks_response := response if {
	_jwks_uri

	response := _cached_request(_jwks_uri, _jwks_cache_duration)
}

_jwks_uri := _config.endpoints.jwks_uri

_jwks_uri := _metadata_response.body.jwks_uri if {
	not _config.endpoints.jwks_uri

	_metadata_response.status_code == 200
}

_metadata_response := _cached_request(_metadata_endpoint, _metadata_cache_duration) if {
	not _config.endpoints.jwks_uri
}

_metadata_endpoint := endpoint if {
	_use_oidc_metadata

	issuer := trim_suffix(_claims.iss, "/")
	endpoint := concat("", [issuer, "/.well-known/openid-configuration"])
}

_metadata_endpoint := endpoint if {
	_use_oauth2_metadata

	issuer := trim_suffix(_claims.iss, "/")
	endpoint := concat("", [issuer, "/.well-known/oauth-authorization-server"])
}

_cached_request(url, duration) := http.send({
	"url": url,
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": duration,
	"raise_error": false,
})

default _metadata_cache_duration := 3600

_metadata_cache_duration := _config.endpoints.metadata_cache_duration

default _jwks_cache_duration := 3600

_jwks_cache_duration := _config.endpoints.jwks_cache_duration

default _use_oidc_metadata := false

_use_oidc_metadata if _config.endpoints.use_oidc_metadata

default _use_oauth2_metadata := false

_use_oauth2_metadata if _config.endpoints.use_oauth2_metadata

# regal ignore:line-length
_errors contains "only one of jwks, endpoints.jwks_uri, endpoints.use_oidc_metadata or endpoints.use_oauth2_metadata can be set" if {
	jwks_options := [
		is_object(object.get(_config, ["jwks"], false)),
		is_string(object.get(_config, ["endpoints", "jwks_uri"], false)),
		object.get(_config, ["endpoints", "use_oidc_metadata"], false),
		object.get(_config, ["endpoints", "use_oauth2_metadata"], false),
	]
	count([1 |
		some option in jwks_options
		option == true
	]) > 1
}

_errors contains _metadata_response.error.message if {
	_metadata_response.status_code == 0
}

_errors contains _jwks_response.error.message if {
	_jwks_response.status_code == 0
}
