// Default: permit all statements (baseline)
permit (
    principal,
    action == IamCompliance::Action::"evaluate",
    resource
);

// DENY: Wildcard resource
forbid (
    principal,
    action == IamCompliance::Action::"evaluate",
    resource
)
when { resource.resources.contains("*") };

// DENY: iam:* actions (overly broad IAM)
forbid (
    principal,
    action == IamCompliance::Action::"evaluate",
    resource
)
when { resource.actions.contains("iam:*") };

// DENY: Allow statements without conditions on sensitive services
forbid (
    principal,
    action == IamCompliance::Action::"evaluate",
    resource
)
when {
    resource.effect == "Allow" &&
    resource.hasCondition == false &&
    resource.actions.contains("s3:*")
};