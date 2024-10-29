package lib.jwt

import rego.v1

# METADATA
# description: |
#   Verifies provided `jwt` using keys found under `jwks`in the config object,
#   which may be provided as either an object or a string
verify(jwt, config) if _verify(io.jwt.decode(jwt)[0].alg, jwt, _object_to_json(config.jwks))

_verify("RS256", jwt, keys) if io.jwt.verify_rs256(jwt, keys)

_verify("RS384", jwt, keys) if io.jwt.verify_rs384(jwt, keys)

_verify("RS512", jwt, keys) if io.jwt.verify_rs512(jwt, keys)

_verify("ES256", jwt, keys) if io.jwt.verify_es256(jwt, keys)

_verify("ES384", jwt, keys) if io.jwt.verify_es384(jwt, keys)

_verify("ES512", jwt, keys) if io.jwt.verify_es512(jwt, keys)

_verify("PS256", jwt, keys) if io.jwt.verify_ps256(jwt, keys)

_verify("PS384", jwt, keys) if io.jwt.verify_ps384(jwt, keys)

_verify("PS512", jwt, keys) if io.jwt.verify_ps512(jwt, keys)

_object_to_json(x) := json.marshal(x) if is_object(x)

_object_to_json(x) := x if is_string(x)
