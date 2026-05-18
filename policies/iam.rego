package iam

import rego.v1

# ---------------------------------------------------------------
# IAM Policy Guardrail Rules
#
# Evaluates a user-provided IAM policy against organizational
# security rules. A policy is "permitted" only when it triggers
# zero violations.
#
# Usage:
#   opa eval -i <policy.json> -d policies/ "data.iam.result"
#   opa test policies/ -v
# ---------------------------------------------------------------

default permit := false

permit if {
	count(violations) == 0
}

result := {
	"permit": permit,
	"violations": violations,
}

# Collect all violations
violations contains msg if {
	some msg in deny_actions
}

violations contains msg if {
	some msg in deny_notaction
}

violations contains msg if {
	some msg in deny_passrole_unscoped
}

# ---------------------------------------------------------------
# Rule: Denied actions (Action field)
# Supports wildcards on both sides. Case-insensitive.
# ---------------------------------------------------------------

_denied_actions := {
	# Privilege escalation
	"iam:*",
	"iam:CreateUser",
	"iam:CreateRole",
	"iam:AttachUserPolicy",
	"iam:AttachRolePolicy",
	"iam:PutUserPolicy",
	"iam:PutRolePolicy",
	"iam:CreateAccessKey",
	"iam:UpdateAssumeRolePolicy",
	"iam:CreateLoginProfile",
	"iam:UpdateLoginProfile",
	"iam:DeactivateMFADevice",
	"iam:DeleteVirtualMFADevice",
	"iam:CreateServiceLinkedRole",

	# Persistence and SSO/identity modification
	"sso:*",
	"sso-admin:*",
	"identitystore:*",

	# Account-level destructive actions
	"account:EnableRegion",
	"account:DisableRegion",
	"account:CloseAccount",
	"organizations:LeaveOrganization",
	"organizations:RemoveAccountFromOrganization",
	"organizations:DeleteOrganization",

	# Security control tampering
	"cloudtrail:StopLogging",
	"cloudtrail:DeleteTrail",
	"config:StopConfigurationRecorder",
	"config:DeleteConfigurationRecorder",
	"guardduty:DeleteDetector",
	"guardduty:DisableOrganizationAdminAccount",
	"access-analyzer:DeleteAnalyzer",
	"kms:ScheduleKeyDeletion",
	"kms:DisableKey",
	"ec2:DeleteFlowLogs",
}

deny_actions contains msg if {
	some i, stmt in input.Statement
	stmt.Effect == "Allow"
	actions := _normalize_list(stmt.Action)
	some action in actions
	some denied in _denied_actions
	_actions_match(action, denied)
	msg := sprintf("Statement[%d]: action '%s' matches denied pattern '%s'", [i, action, denied])
}

# ---------------------------------------------------------------
# Rule: NotAction is effectively "allow everything except X"
#
# If a statement uses NotAction with Effect: Allow, it grants
# all actions EXCEPT the listed ones. This almost certainly
# covers denied actions unless the NotAction list explicitly
# excludes every single denied action (which is impractical).
#
# Strategy: if NotAction is used with Allow, check whether any
# denied action is NOT covered by the NotAction exclusion list.
# If so, the statement implicitly grants that denied action.
# ---------------------------------------------------------------

deny_notaction contains msg if {
	some i, stmt in input.Statement
	stmt.Effect == "Allow"
	stmt.NotAction
	excluded := _normalize_list(stmt.NotAction)
	some denied in _denied_actions
	not _any_covers(excluded, denied)
	msg := sprintf("Statement[%d]: NotAction allows denied action '%s' (not excluded)", [i, denied])
}

# True if any pattern in the list covers the target
_any_covers(patterns, target) if {
	some pattern in patterns
	_actions_match(pattern, target)
}

# ---------------------------------------------------------------
# Rule: iam:PassRole must be scoped
# Requires:
#   1. Resource is NOT "*"
#   2. Condition includes iam:PassedToService
# ---------------------------------------------------------------

deny_passrole_unscoped contains msg if {
	some i, stmt in input.Statement
	stmt.Effect == "Allow"
	actions := _normalize_list(stmt.Action)
	some action in actions
	_actions_match(action, "iam:PassRole")
	_resource_is_star(stmt)
	msg := sprintf("Statement[%d]: iam:PassRole requires a scoped Resource, not '*'", [i])
}

deny_passrole_unscoped contains msg if {
	some i, stmt in input.Statement
	stmt.Effect == "Allow"
	actions := _normalize_list(stmt.Action)
	some action in actions
	_actions_match(action, "iam:PassRole")
	not _has_passed_to_service_condition(stmt)
	msg := sprintf("Statement[%d]: iam:PassRole requires a Condition with 'iam:PassedToService'", [i])
}
