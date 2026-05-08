#!/usr/bin/env python3
import json
import sys

def extract_iam_policies(tfplan_path):
    with open(tfplan_path) as f:
        plan = json.load(f)

    entities = []
    statements = []

    # Add the compliance engine principal
    entities.append({
        "uid": {"type": "IamCompliance::ComplianceEngine", "id": "engine"},
        "attrs": {},
        "parents": []
    })

    # Walk through resource changes looking for IAM policies
    for rc in plan.get("resource_changes", []):
        if rc["type"] in ("aws_iam_policy", "aws_iam_role_policy"):
            after = rc.get("change", {}).get("after", {})
            policy_doc = json.loads(after.get("policy", "{}"))

            for idx, stmt in enumerate(policy_doc.get("Statement", [])):
                stmt_id = f"{rc['address']}-stmt-{idx}"
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                entities.append({
                    "uid": {"type": "IamCompliance::IamStatement", "id": stmt_id},
                    "attrs": {
                        "effect": stmt.get("Effect", "Allow"),
                        "actions": actions,
                        "resources": resources,
                        "hasCondition": "Condition" in stmt,
                        "sourceFile": rc["address"]
                    },
                    "parents": []
                })
                statements.append(stmt_id)

    return entities, statements

if __name__ == "__main__":
    entities, _ = extract_iam_policies(sys.argv[1])
    print(json.dumps(entities, indent=2))