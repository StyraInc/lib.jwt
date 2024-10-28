package example.app

import rego.v1

import data.lib.jwt

# METADATA
# entrypoint: true
allow if {
	"admin" in jwt.claims.user.roles
}
