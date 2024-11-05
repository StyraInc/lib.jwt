package libraries.jwt

import rego.v1

# METADATA
# description: converts given nanoseconds to seconds (rounded to integer)
nanos_to_seconds(nanos) := round(nanos / 1000000000)
