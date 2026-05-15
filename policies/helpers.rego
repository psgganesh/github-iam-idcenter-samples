package iam

import rego.v1

# ---------------------------------------------------------------
# Helpers: IAM wildcard matching and utility functions
# ---------------------------------------------------------------

# Bidirectional match — true if either pattern covers the other.
# Case-insensitive, matching real IAM behavior.
_actions_match(a, b) if {
	_glob_covers(lower(a), lower(b))
}

_actions_match(a, b) if {
	_glob_covers(lower(b), lower(a))
}

# Does pattern (with * and ?) cover the target string?
_glob_covers(pattern, target) if {
	regex.match(_to_regex(pattern), target)
}

# Convert IAM glob (*, ?) to anchored regex
_to_regex(glob) := pattern if {
	escaped := regex.replace(glob, `([\.\+\^\$\|\(\)\[\]\{\}\\])`, `\\$1`)
	step1 := replace(escaped, "*", ".*")
	step2 := replace(step1, "?", ".")
	pattern := sprintf("^%s$", [step2])
}

# Normalize a string-or-array value into an array
_normalize_list(value) := [value] if {
	is_string(value)
}

_normalize_list(value) := value if {
	is_array(value)
}

# Check if Resource includes "*"
_resource_is_star(stmt) if {
	stmt.Resource == "*"
}

_resource_is_star(stmt) if {
	is_array(stmt.Resource)
	some r in stmt.Resource
	r == "*"
}

# Check if Condition references iam:PassedToService
_has_passed_to_service_condition(stmt) if {
	some _, keys in stmt.Condition
	keys["iam:PassedToService"]
}
