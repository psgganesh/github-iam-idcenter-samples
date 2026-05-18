package iam

import rego.v1

# ---------------------------------------------------------------
# Run all tests: opa test policies/ -v
# ---------------------------------------------------------------

# === Should PASS ===

test_ec2_in_region_denied if {
	# ec2:* covers ec2:DeleteFlowLogs which is in the denied list.
	# Even with a region condition, the wildcard is too broad.
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Action": "ec2:*",
			"Resource": "*",
			"Effect": "Allow",
			"Condition": {"StringEquals": {"ec2:Region": "us-east-2"}},
		}],
	}
}

test_ec2_scoped_actions_permitted if {
	# Use specific ec2 actions instead of ec2:*
	permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["ec2:RunInstances", "ec2:DescribeInstances", "ec2:StartInstances"],
			"Resource": "*",
			"Condition": {"StringEquals": {"ec2:Region": "us-east-2"}},
		}],
	}
}

test_launch_instances_permitted if {
	permit with input as {
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["ec2:Describe*", "ec2:GetConsole*"],
				"Resource": "*",
			},
			{
				"Effect": "Allow",
				"Action": "ec2:RunInstances",
				"Resource": [
					"arn:aws:ec2:*:*:subnet/subnet-subnet-id",
					"arn:aws:ec2:*:*:network-interface/*",
					"arn:aws:ec2:*:*:instance/*",
					"arn:aws:ec2:*:*:volume/*",
					"arn:aws:ec2:*::image/ami-*",
					"arn:aws:ec2:*:*:key-pair/*",
					"arn:aws:ec2:*:*:security-group/*",
				],
			},
		],
	}
}

test_s3_read_permitted if {
	permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:ListBucket"],
			"Resource": "arn:aws:s3:::my-bucket/*",
		}],
	}
}

test_deny_effect_always_permitted if {
	permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Action": "iam:*",
			"Resource": "*",
		}],
	}
}

test_unrelated_action_permitted if {
	permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "organizations:DescribeOrganization",
			"Resource": "*",
		}],
	}
}

test_cloudtrail_read_permitted if {
	permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus"],
			"Resource": "*",
		}],
	}
}

# === Privilege escalation ===

test_iam_wildcard_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:*",
			"Resource": "*",
		}],
	}
}

test_iam_create_user_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:CreateUser",
			"Resource": "*",
		}],
	}
}

test_iam_create_role_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:CreateRole",
			"Resource": "*",
		}],
	}
}

test_iam_attach_user_policy_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:AttachUserPolicy",
			"Resource": "*",
		}],
	}
}

test_iam_attach_role_policy_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:AttachRolePolicy",
			"Resource": "*",
		}],
	}
}

test_iam_put_user_policy_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:PutUserPolicy",
			"Resource": "*",
		}],
	}
}

test_iam_put_role_policy_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:PutRolePolicy",
			"Resource": "*",
		}],
	}
}

test_iam_create_access_key_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:CreateAccessKey",
			"Resource": "*",
		}],
	}
}

test_iam_update_assume_role_policy_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:UpdateAssumeRolePolicy",
			"Resource": "*",
		}],
	}
}

test_iam_create_login_profile_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:CreateLoginProfile",
			"Resource": "*",
		}],
	}
}

test_iam_deactivate_mfa_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:DeactivateMFADevice",
			"Resource": "*",
		}],
	}
}

# === Persistence and SSO/identity manipulation ===

test_sso_wildcard_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "sso:*",
			"Resource": "*",
		}],
	}
}

test_sso_admin_wildcard_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "sso-admin:*",
			"Resource": "*",
		}],
	}
}

test_identitystore_wildcard_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "identitystore:*",
			"Resource": "*",
		}],
	}
}

test_sso_specific_action_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "sso:CreatePermissionSet",
			"Resource": "*",
		}],
	}
}

test_sso_admin_specific_action_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "sso-admin:AttachManagedPolicyToPermissionSet",
			"Resource": "*",
		}],
	}
}

# === Account-level destructive actions ===

test_account_close_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "account:CloseAccount",
			"Resource": "*",
		}],
	}
}

test_organizations_leave_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "organizations:LeaveOrganization",
			"Resource": "*",
		}],
	}
}

test_organizations_remove_account_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "organizations:RemoveAccountFromOrganization",
			"Resource": "*",
		}],
	}
}

test_organizations_delete_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "organizations:DeleteOrganization",
			"Resource": "*",
		}],
	}
}

test_account_enable_region_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "account:EnableRegion",
			"Resource": "*",
		}],
	}
}

# === Security control tampering ===

test_cloudtrail_stop_logging_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "cloudtrail:StopLogging",
			"Resource": "*",
		}],
	}
}

test_cloudtrail_delete_trail_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "cloudtrail:DeleteTrail",
			"Resource": "*",
		}],
	}
}

test_config_stop_recorder_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "config:StopConfigurationRecorder",
			"Resource": "*",
		}],
	}
}

test_config_delete_recorder_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "config:DeleteConfigurationRecorder",
			"Resource": "*",
		}],
	}
}

test_guardduty_delete_detector_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "guardduty:DeleteDetector",
			"Resource": "*",
		}],
	}
}

test_guardduty_disable_org_admin_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "guardduty:DisableOrganizationAdminAccount",
			"Resource": "*",
		}],
	}
}

test_access_analyzer_delete_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "access-analyzer:DeleteAnalyzer",
			"Resource": "*",
		}],
	}
}

test_kms_schedule_key_deletion_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "kms:ScheduleKeyDeletion",
			"Resource": "*",
		}],
	}
}

test_kms_disable_key_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "kms:DisableKey",
			"Resource": "*",
		}],
	}
}

test_ec2_delete_flow_logs_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "ec2:DeleteFlowLogs",
			"Resource": "*",
		}],
	}
}

# === Wildcard evasion ===

test_organizations_star_evasion_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "organizations:*",
			"Resource": "*",
		}],
	}
}

test_organizations_question_mark_evasion_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "organizations:L?aveOrganization",
			"Resource": "*",
		}],
	}
}

test_cloudtrail_star_evasion_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "cloudtrail:*",
			"Resource": "*",
		}],
	}
}

test_guardduty_star_evasion_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "guardduty:Delete*",
			"Resource": "*",
		}],
	}
}

# === PassRole scoping ===

test_passrole_star_resource_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:PassRole",
			"Resource": "*",
			"Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}},
		}],
	}
}

test_passrole_no_condition_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:PassRole",
			"Resource": "arn:aws:iam::123456789012:role/MyAppRole",
		}],
	}
}

test_passrole_wrong_condition_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:PassRole",
			"Resource": "arn:aws:iam::123456789012:role/MyAppRole",
			"Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
		}],
	}
}

# === NotAction evasion ===

test_notaction_allows_denied_actions if {
	# NotAction "s3:GetObject" with Allow means everything EXCEPT s3:GetObject
	# is granted, including all denied actions.
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"NotAction": "s3:GetObject",
			"Resource": "*",
		}],
	}
}

test_notaction_array_allows_denied_actions if {
	# Excluding a few harmless actions still leaves denied actions granted.
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"NotAction": ["s3:GetObject", "s3:PutObject", "lambda:InvokeFunction"],
			"Resource": "*",
		}],
	}
}

test_notaction_excluding_all_iam_still_fails if {
	# Even if you exclude iam:*, other denied actions like cloudtrail:StopLogging
	# are still implicitly allowed.
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"NotAction": "iam:*",
			"Resource": "*",
		}],
	}
}

test_notaction_with_deny_effect_permitted if {
	# NotAction with Deny is fine - it denies everything except the listed action.
	# This is a common restrictive pattern.
	permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"NotAction": "s3:GetObject",
			"Resource": "*",
		}],
	}
}

# === Case sensitivity evasion ===

test_case_evasion_uppercase_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "IAM:CreateUser",
			"Resource": "*",
		}],
	}
}

test_case_evasion_mixed_case_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "Iam:createuser",
			"Resource": "*",
		}],
	}
}

test_case_evasion_cloudtrail_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "CLOUDTRAIL:StopLogging",
			"Resource": "*",
		}],
	}
}

test_case_evasion_organizations_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "Organizations:LEAVEORGANIZATION",
			"Resource": "*",
		}],
	}
}

test_case_evasion_wildcard_denied if {
	# IAM:* should still match iam:* rule
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "IAM:*",
			"Resource": "*",
		}],
	}
}


# === iam:CreateServiceLinkedRole ===

test_create_service_linked_role_denied if {
	not permit with input as {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "iam:CreateServiceLinkedRole",
			"Resource": "*",
		}],
	}
}
