# METADATA
# description: Example application using lib.jwt
# schemas:
#   - data.lib.jwt: schema["lib.jwt.schema"]
package example.app

import data.lib.jwt

# METADATA
# description: whether the request is allowed or not
decision["allow"] if _allow

# METADATA
# description: list of reasons why the request was denied, only present when there have been errors reported
decision["reasons"] := jwt.errors if count(jwt.errors) > 0

_allow if "admin" in jwt.claims.user.roles
