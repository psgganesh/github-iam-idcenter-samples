
# =============================================================================
# main.tf - Terraform project with 5 IAM Policies that VIOLATE Cedar rules
# =============================================================================
# 
# Violations mapped to Cedar rules:
#   Policy 1: Wildcard resource (*)
#   Policy 2: iam:* actions (overly broad IAM)
#   Policy 3: s3:* without condition
#   Policy 4: Wildcard resource (*) + no condition
#   Policy 5: iam:* + wildcard resource (*) (multiple violations)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-2"
}

variable "qda_id" {
  description = "QDA Application ID"
  type        = string
  default     = "QDA-APP-001"
}

# =============================================================================
# POLICY 1: VIOLATES → "forbid wildcard resource"
# Uses Resource: "*" which is caught by:
#   forbid ... when { resource.resources.contains("*") };
# =============================================================================
resource "aws_iam_policy" "violation_wildcard_resource" {
  name        = "${var.qda_id}-custom-role-wildcard-resource"
  description = "VIOLATION: Uses wildcard (*) in Resource"
  path        = "/qda/custom-roles/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEC2DescribeAll"
        Effect   = "Allow"
        Action   = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# POLICY 2: VIOLATES → "forbid iam:* actions"
# Uses Action: "iam:*" which is caught by:
#   forbid ... when { resource.actions.contains("iam:*") };
# =============================================================================
resource "aws_iam_policy" "violation_iam_wildcard_actions" {
  name        = "${var.qda_id}-custom-role-iam-wildcard"
  description = "VIOLATION: Uses iam:* action (overly broad IAM permissions)"
  path        = "/qda/custom-roles/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullIAMAccess"
        Effect   = "Allow"
        Action   = "iam:*"
        Resource = "arn:aws:iam::123456789012:role/QDA-*"
      }
    ]
  })
}

# =============================================================================
# POLICY 3: VIOLATES → "forbid s3:* without condition"
# Uses Action: "s3:*" with Effect: "Allow" and NO Condition, caught by:
#   forbid ... when {
#     resource.effect == "Allow" &&
#     resource.hasCondition == false &&
#     resource.actions.contains("s3:*")
#   };
# =============================================================================
resource "aws_iam_policy" "violation_s3_wildcard_no_condition" {
  name        = "${var.qda_id}-custom-role-s3-no-condition"
  description = "VIOLATION: s3:* Allow without any Condition block"
  path        = "/qda/custom-roles/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullS3AccessNoCondition"
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = [
          "arn:aws:s3:::qda-app-001-data-bucket",
          "arn:aws:s3:::qda-app-001-data-bucket/*"
        ]
      }
    ]
  })
}

# =============================================================================
# POLICY 4: VIOLATES → "forbid wildcard resource" (again, different context)
# Multi-statement policy where one statement uses Resource: "*" without condition
# Also demonstrates a "safe" statement alongside a violating one
# =============================================================================
resource "aws_iam_policy" "violation_mixed_statements" {
  name        = "${var.qda_id}-custom-role-mixed-violations"
  description = "VIOLATION: Contains both compliant and non-compliant statements"
  path        = "/qda/custom-roles/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # This statement is COMPLIANT (specific resource + condition)
        Sid      = "AllowDynamoDBWithCondition"
        Effect   = "Allow"
        Action   = [
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = "arn:aws:dynamodb:ap-southeast-2:123456789012:table/QDA-*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "ap-southeast-2"
          }
        }
      },
      {
        # This statement VIOLATES: wildcard resource
        Sid      = "AllowCloudWatchEverything"
        Effect   = "Allow"
        Action   = [
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics",
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# POLICY 5: VIOLATES → MULTIPLE RULES (worst offender)
# - Uses iam:* actions
# - Uses Resource: "*"
# - No condition on Allow
# Triggers ALL THREE forbid rules simultaneously
# =============================================================================
resource "aws_iam_policy" "violation_multiple_rules" {
  name        = "${var.qda_id}-custom-role-multi-violation"
  description = "VIOLATION: Breaks multiple Cedar rules - iam:*, wildcard resource, no condition"
  path        = "/qda/custom-roles/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GodModeIAM"
        Effect = "Allow"
        Action = [
          "iam:*",
          "s3:*",
          "sts:AssumeRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# IAM Roles for the custom policies (simulating QDA custom role provisioning)
# =============================================================================
resource "aws_iam_role" "custom_role_1" {
  name = "${var.qda_id}-CUSTOM-ROLE-EC2-OPS"
  path = "/qda/custom-roles/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "account-access.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "custom_role_2" {
  name = "${var.qda_id}-CUSTOM-ROLE-IAM-ADMIN"
  path = "/qda/custom-roles/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "account-access.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "custom_role_3" {
  name = "${var.qda_id}-CUSTOM-ROLE-DATA-ENG"
  path = "/qda/custom-roles/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "account-access.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "custom_role_4" {
  name = "${var.qda_id}-CUSTOM-ROLE-MONITORING"
  path = "/qda/custom-roles/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "account-access.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "custom_role_5" {
  name = "${var.qda_id}-CUSTOM-ROLE-SUPER-ADMIN"
  path = "/qda/custom-roles/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "account-access.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# =============================================================================
# Policy Attachments - Link policies to roles
# =============================================================================
resource "aws_iam_role_policy_attachment" "attach_1" {
  role       = aws_iam_role.custom_role_1.name
  policy_arn = aws_iam_policy.violation_wildcard_resource.arn
}

resource "aws_iam_role_policy_attachment" "attach_2" {
  role       = aws_iam_role.custom_role_2.name
  policy_arn = aws_iam_policy.violation_iam_wildcard_actions.arn
}

resource "aws_iam_role_policy_attachment" "attach_3" {
  role       = aws_iam_role.custom_role_3.name
  policy_arn = aws_iam_policy.violation_s3_wildcard_no_condition.arn
}

resource "aws_iam_role_policy_attachment" "attach_4" {
  role       = aws_iam_role.custom_role_4.name
  policy_arn = aws_iam_policy.violation_mixed_statements.arn
}

resource "aws_iam_role_policy_attachment" "attach_5" {
  role       = aws_iam_role.custom_role_5.name
  policy_arn = aws_iam_policy.violation_multiple_rules.arn
}

# =============================================================================
# Outputs
# =============================================================================
output "policy_arns" {
  description = "ARNs of created policies (all should FAIL Cedar validation)"
  value = {
    "1_wildcard_resource"       = aws_iam_policy.violation_wildcard_resource.arn
    "2_iam_wildcard_actions"    = aws_iam_policy.violation_iam_wildcard_actions.arn
    "3_s3_no_condition"         = aws_iam_policy.violation_s3_wildcard_no_condition.arn
    "4_mixed_statements"        = aws_iam_policy.violation_mixed_statements.arn
    "5_multiple_violations"     = aws_iam_policy.violation_multiple_rules.arn
  }
}

output "role_arns" {
  description = "ARNs of created IAM roles"
  value = {
    "1_ec2_ops"      = aws_iam_role.custom_role_1.arn
    "2_iam_admin"    = aws_iam_role.custom_role_2.arn
    "3_data_eng"     = aws_iam_role.custom_role_3.arn
    "4_monitoring"   = aws_iam_role.custom_role_4.arn
    "5_super_admin"  = aws_iam_role.custom_role_5.arn
  }
}

