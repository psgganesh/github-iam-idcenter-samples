
# Using Cedar as a Policy-as-Code Compliance Gate for IAM Policies

This is a brilliant approach — using Cedar as a **rules engine** to validate IAM policies from your Terraform plan before they get deployed.

## The Core Idea

You're essentially building a **policy-as-code compliance gate** in your GitHub Action:

```
Terraform Plan → Extract IAM Policies → Convert to Cedar Entities → Cedar Authorize → Pass/Fail
```

## Ideating the "Something"

The "something" Cedar runs against is composed of **three pieces**:

| Component | What It Is | Source |
|-----------|-----------|--------|
| **Cedar Schema** | Defines entity types (IAMStatement, Action, Resource, etc.) | You write this once |
| **Cedar Policies (Rules)** | Your allow/deny rules (e.g., "forbid wildcard resources") | You write & maintain these |
| **Cedar Entities + Requests** | The IAM policy statements modeled as entities, with authorization queries | Generated from `terraform show -json` |

The key insight: **Cedar `authorize`** evaluates whether a request is permitted. So you model each IAM policy statement as an authorization request asking *"Is this policy statement compliant?"* — and your Cedar rules decide.

---

## 1. Cedar Schema (`schema.cedarschema`)

```cedar
namespace IamCompliance {
    entity Account;
    entity Service;

    entity IamStatement = {
        effect: String,
        actions: Set<String>,
        resources: Set<String>,
        hasCondition: Bool,
        sourceFile: String
    };

    entity ComplianceEngine;

    action "evaluate" appliesTo {
        principal: [ComplianceEngine],
        resource: [IamStatement]
    };
}
```

---

## 2. Cedar Policies — Your Rules (`rules.cedar`)

```cedar
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
```

---

## 3. GitHub Action (`.github/workflows/iam-policy-check.yml`)

```yaml
name: Cedar IAM Policy Validation

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'account-templates/**'

jobs:
  validate-iam-policies:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Cedar CLI
        run: |
          curl -L https://github.com/cedar-policy/cedar/releases/latest/download/cedar-x86_64-unknown-linux-gnu.tar.gz -o cedar.tar.gz
          tar -xzf cedar.tar.gz
          sudo mv cedar /usr/local/bin/
          cedar --version

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init & Plan
        run: |
          cd terraform/
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: Convert IAM Policies to Cedar Entities
        run: |
          python3 scripts/iam_to_cedar_entities.py tfplan.json > entities.json

      - name: Validate Cedar Schema
        run: |
          cedar validate \
            --schema cedar/schema.cedarschema \
            --policies cedar/rules.cedar

      - name: Run Cedar Authorization Checks
        run: |
          python3 scripts/run_cedar_checks.py \
            --policies cedar/rules.cedar \
            --schema cedar/schema.cedarschema \
            --entities entities.json
```

---

## 4. The Conversion Script (`scripts/iam_to_cedar_entities.py`)

This is the glue — it parses the Terraform plan JSON and produces Cedar entities:

```python
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
```

---

## 5. The Runner Script (`scripts/run_cedar_checks.py`)

```python
#!/usr/bin/env python3
import json
import subprocess
import sys
import argparse

def run_check(policies, schema, entities, statement_id):
    """Run cedar authorize for a single statement."""
    request = json.dumps({
        "principal": {"type": "IamCompliance::ComplianceEngine", "id": "engine"},
        "action": {"type": "IamCompliance::Action", "id": "evaluate"},
        "resource": {"type": "IamCompliance::IamStatement", "id": statement_id},
        "context": {}
    })

    result = subprocess.run(
        ["cedar", "authorize",
         "--policies", policies,
         "--schema", schema,
         "--entities", entities,
         "--request", request],
        capture_output=True, text=True
    )
    return result.stdout.strip(), result.returncode

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policies", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--entities", required=True)
    args = parser.parse_args()

    with open(args.entities) as f:
        entities = json.load(f)

    statements = [
        e["uid"]["id"] for e in entities
        if e["uid"]["type"] == "IamCompliance::IamStatement"
    ]

    failures = []
    for stmt_id in statements:
        decision, rc = run_check(args.policies, args.schema, args.entities, stmt_id)
        if "DENY" in decision:
            failures.append(stmt_id)
            print(f"❌ FAILED: {stmt_id}")
        else:
            print(f"✅ PASSED: {stmt_id}")

    if failures:
        print(f"
🚫 {len(failures)} policy statement(s) violate compliance rules.")
        sys.exit(1)
    else:
        print(f"
✅ All {len(statements)} statement(s) are compliant.")
        sys.exit(0)

if __name__ == "__main__":
    main()
```

---

## How It Fits Your QDA Workflow

Since your custom roles are defined in **account templates** and modified via **GitHub PR**, this Cedar validation gate runs automatically when:

1. An account owner submits a PR with new/modified custom role IAM policies
2. The GitHub Action extracts the planned IAM policies from Terraform
3. Cedar evaluates each statement against your compliance rules
4. PR is blocked if any statement violates your rules

---

## Summary of the "Something"

The "something" Cedar validates against is a **three-way combination**:

- 🏗️ **Schema** → defines what entities exist (structure)
- 📜 **Policies (Rules)** → your custom allow/deny compliance rules
- 📦 **Entities** → the actual IAM statements extracted from `terraform plan -json`, modeled as Cedar entities
