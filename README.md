# lib.jwt

An opinionated library for safely verifying and decoding JSON Web Tokens (JWTs) in Rego.

## Features

- A fully [configuration-driven approach](#configuration-driven-verification) to token verification
- Or if you prefer, use like a traditional library — import and use verification [functions](#functions)
- Support for OAuth 2.0 and OpenID Connect metadata endpoints for retrieving verification keys without configuration
- Default verification constraints based on [best practices](https://datatracker.ietf.org/doc/html/rfc8725)
- Clear error messages, describing exactly which constraints failed and why

### Opinionated for Security

While most constraints are configurable/optional, we strongly feel that the following constraints should be enforced,
and as such, they can't be disabled:

1. Only assymetric algorithms supported — HMAC should not be used for policy use cases
2. The issuer (`iss`) claim is required — blindly accepting tokens from any issuer is a bad idea
3. The `exp` claim is required — any tokens issued should have a limited lifetime
4. The `nbf` (not before) claim will always be verified to be later than current time if present in token

If your need to verify tokens without these constraints, use the built-in
[io.jwt](https://www.openpolicyagent.org/docs/latest/policy-reference/#tokens) functions instead.

## Usage

### Configuration

At the heart of the library is the `config` object. This object typically contains the allowed issuer(s), the JWKS data
to use for verification, or the method to use to retrieve it.

Example configuration using an OpenID Connect metadata endpoint to retrieve public keys for signature verification:

```json
{
  "allowed_issuers": ["https://identity.example.com"],
  "endpoints": {
    "use_oidc_metadata": true
  }
}
```

Example configuration providing an RSA public key for verification:

```json
{
  "allowed_issuers": ["https://identity.example.com"],
  "allowed_algorithms": ["RS512", "ES512"],
  "jwks": {
    "keys": [
      {
        "kty": "RSA",
        "n": "0uUZ4XpiWu4ds6SxR-5xH6Lxu45mwgw6FDfZVZ-vGu1tsuZaUgdrJ-smKVX4L7Qa_q2pKPPepKnWhlktwXYNIk1ILkWSMLCBBzTWgulh5TTl3WCPjpzLKS4ZX0uoCt3wylIozzDIajGpSLve_xQ6G56FtZwlUC1lMPRBOV3ULOXAP24u5fwmWE6kX_rj6VW7Q4FpWo5kIQsNIukGzX6JznbxgX9NDWXpXgD8-MhnLIWtfPFK5S-BFoQGk4fXyuOVTcWFecwlh9SPbeCSQrVv1GnXFdGW1lFljK9QIhXWK38D7mdD279jrw9UW065ktnfZ4VxjjPa2COAzYEA85eRZQ",
        "e": "AQAB"
      }
    ]
  }
}
```

The `config` object can either be passed to the `jwt.decode_verify` function directly, or provided as part of e.g.
a bundle `data.json` file for an entirely configuration-driven approach.

#### Configuration Attributes

- `allowed_issuers` - **required** list of allowed issuers where one must match the `iss` claim from the JWT
- `allowed_audiences` - **optional** list of allowed audiences, where at least one audience must match the `aud`
  claim value(s) from the token (which must have an `aud` claim if this attribute is present)
- `allowed_algorithms` - **optional** list of allowed algorithms
  (default: `["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]`)
- `jwks` - **optional** the JWK Set object to use for verifying tokens
- `input_path_jwt` - **optional** the path in the `input` document where the library should look for the JWT
  when using the [config-based approach](#configuration-driven-verification)
- `time` - **optional** the time to use for verification, UNIX epoch time, seconds (default: current time)
- `leeway` - **optional** the leeway in seconds to allow for `exp`, `nbf` and `iat` claims (default: `0`)
- `endpoints`
  - `use_oidc_metadata` - **optional** set to `true` use OpenID Connect metadata endpoint for retrieving JWKS data
  - `use_oauth2_metadata` - **optional** set to `true` use OAuth 2.0 metadata endpoint for retrieving JWKS data
  - `jwks_uri` - **optional** URL to a JWKS endpoint to use for verifying tokens
  - `metadata_cache_duration` - **optional** duration in seconds to cache metadata (default: `3600`)
  - `jwks_cache_duration` - **optional** duration in seconds to cache JWKS data (default: `3600`)

#### Using `endpoints`

In scenarios where OAuth 2.0 or OpenID Connect is used, public key materials (JWKS) can be retrieved via the metadata
endpoint — and its pointer to a `jwks_uri` — of the issuer (i.e. `iss` claim from the token). This is a convenient way
to defer distribution of keys to an identity server rather than embedding them in OPA's data or policies.

Note that all requests to metadata or JWKS endpoints are cached for a configurable duration (default, 1 hour). Setting
this to the highest possible duration is recommended to avoid unnecessary requests to the issuer's endpoints.

## Configuration-driven Verification

This library offers a novel approach to handling settings, as it'll automatically search for configuration under the
path `data.lib.config.jwt`, and if found, use it for verification. When this configuration contains an `input_path_jwt`
attribute, the library will look for the JWT at the specified path in the `input` document, and verify it without the
need for custom code in the user's policy. This results in policies where the focus is authorization logic rather than
JWT verification details, and requirements that can change simply by updating the configuration.

### Example

Given a bundle containing a `data.json` or `data.yaml` at its root, where the configuration is stored under
`lib.config.jwt`, and an `input` document containing tokens for verification under `input.token`:

**data.json**

```json
{
  "lib": {
    "config": {
      "jwt": {
        "allowed_issuers": [
          "https://issuer1.example.com"
        ],
        "endpoints": {
          "use_oidc_metadata": true
        },
        "input_path_jwt": "input.token"
      }
    }
  }
}
```

Authorization policies are now able to use the attributes from the `jwt` object directly, and without explicitly
calling the `jwt.decode_verify` function:

```rego
package app.authz

import data.lib.jwt

allow if "admin" in jwt.claims.user.roles
```

Both methods work equally well, and the choice between them is largely a matter of preference. The difference is mainly
where the call to `jwt.decode_verify` is made.

## Functions

All examples above assume `data.lib.jwt` is imported in the policy.

### `jwt.decode_verify(jwt, config)`

Verifies the provided `jwt` using the given `config` object, which in addition to required attributes (like
`allowed_issuers`) and a method to verify the signature (either a `jwks` object or a reference to a remote
metadata or JWKS endpoint), may also include optional attributes that when present will be used to further
verify the token.

**Returns:** an object containing the following properties:

- `header` - the decoded header from the JWT, if all verification requirements are met
- `claims` - the decoded claims from the JWT, if all verification requirements are met
- `errors` - a list of errors encountered during verification

Neither the `header` nor the `claims` properties will be present if any verification requirements failed
to be met.

#### Example

A simple example of a policy using the `jwt.decode_verify` function might look like this:

```rego
package app.authz

import data.lib.jwt

allow if "admin" in verified.claims.user.roles

allow if {
    # ... other conditions ...
}

verified := jwt.decode_verify(input.token, {
    "allowed_issuers": ["https://identity.example.com"],
    "allowed_algorithms": ["RS256"],
    "jwks": {
        "keys": [{
            "kty": "RSA",
            "n": "0uUZ4XpiWu4ds6SxR.....",
            "e": "AQAB"
        }]
    }
})
```

## Enforcing Usage

Some organizations may want to enforce the use of this library and prevent using the built-in JWT functions directly.
This can be achieved using two different approaches.

### Regal

Another, more flexible option, is to use [Regal](https://docs.styra.com/regal) and the custom
[forbidden-function-call](https://docs.styra.com/regal/rules/custom/forbidden-function-call) rule to ensure that none
of the built-in JWT functions are used directly (or at least, only a subset of them). An example Regal configuration to
forbid the use of any built-in function for verification of JWTs might like this:

```yaml
rules:
  custom:
    forbidden-function-call:
      level: error
      ignore:
        files:
          # allow only in libraries
          - lib/**
      forbidden-functions:
        - io.jwt.decode_verify
        - io.jwt.verify_hs256
        - io.jwt.verify_hs384
        - io.jwt.verify_hs512
        - io.jwt.verify_rs256
        - io.jwt.verify_rs384
        - io.jwt.verify_rs512
        - io.jwt.verify_es256
        - io.jwt.verify_es384
        - io.jwt.verify_es512
        - io.jwt.verify_ps256
        - io.jwt.verify_ps384
        - io.jwt.verify_ps512
```

Note how anything under the `lib` directory is excepted from the rule, allowing this library (and possibly others)
to handle verification.

### Capabilities

The first option is to use the
[capabilities feature](https://www.openpolicyagent.org/docs/latest/deployments/#capabilities) of OPA to restrict the
available built-in functions at the time of building a bundle for production (likely in CI/CD).

To obtain the capabilities JSON object for the current version of OPA:

```shell
opa capabilities --current > capabilities.json
```

Edit the file to remove any undesired built-in functions, then build your bundle with the `--capabilities` flag:

```shell
opa build --capabilities capabilities.json --bundle policy/
```

**Note** that this however requires that the `policy` bundle (from the example) is built separately from this library!


## `lib.jwt` vs. `io.jwt.decode_verify`

While OPA provides several built-in functions for working with JWTs under the `io.jwt` namespace, it leaves users with
two options for verifying tokens, including standard claims such as `exp` and `iss`:

1. Use the built-in `io.jwt.decode_verify` function to verify the signature along with any provided constraints.
   This however comes with a pretty significant limitation: there's no way to know (or communicate) which of the
   constraints failed. Wether the signature was invalid, the token was expired, or the issuer was unknown, the
   function will simply evaluate to `false` without providing any additional details.
2. Decode and verify separately using `io.jwt.decode` and one or more of the `io.jwt.verify_*` variants. This is
   often the preferred option, as it allows for more granular control over the verification process. It does however
   lack the convenience of the `io.jwt.decode_verify` function, and perhaps more importantly will have teams everywhere
   reimplementing claims verification logic.

This library attempts to bridge the gap between these two options by providing a set of functions and rules to help
users verify JWTs and related claims in a more standardized manner.

## Testing

To create JWKs from PEMs, [jwker](https://github.com/jphastings/jwker) is a useful tool.

### Keys

#### Generate RSA keys

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
jwker public.pem public.jwk
jwker private.pem private.jwk
```

#### Generate ECDSA keys

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
jwker public.pem public.jwk
jwker private.pem private.jwk
```

