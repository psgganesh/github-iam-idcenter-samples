# IAM Policy Compliance Gate

A **policy-as-code compliance gate** that validates AWS IAM policies from Terraform plans against organisational security rules using OPA (Open Policy Agent), integrated into GitHub Actions.

## The Core Idea

```
Terraform Plan → Extract IAM Policies → OPA Evaluate → Pass/Fail
```

Each IAM policy statement planned by Terraform is extracted and evaluated against Rego rules. If any statement violates a rule, the pipeline blocks deployment.

## Repository Structure

```
github-iam-idcenter-samples/
├── .github/
│   └── workflows/
│       └── iam-policy-check.yml          # GitHub Action — runs the compliance gate
│
├── policies/
│   ├── helpers.rego                      # Utility functions (glob matching, case normalization)
│   ├── iam.rego                          # Security rules (denied actions, NotAction, PassRole)
│   └── iam_test.rego                     # OPA tests
│
├── scripts/
│   ├── iam_to_cedar_entities.py          # Converts tfplan.json → Cedar entities (experimental)
│   └── run_cedar_checks.py              # Runs Cedar authorize per statement (experimental)
│
├── terraform/
│   ├── main.tf                          # Sample IAM policies & roles (intentional violations)
│   ├── variables.tf
│   ├── outputs.tf
│   └── backend.tf
│
└── README.md
```

## How It Works

1. **Terraform Plan** — generates a JSON plan containing all IAM policy resources
2. **Extract** — a Python script parses `tfplan.json` and writes each IAM policy document as a separate JSON file
3. **OPA Evaluate** — each policy file is evaluated against the Rego rules in `policies/`
4. **Pass/Fail** — if any policy returns `permit: false`, the workflow fails the PR

### Pipeline Flow (GitHub Actions)

The workflow in `.github/workflows/iam-policy-check.yml` runs on pushes to `dev/opa` and PRs to `main`:

```yaml
Checkout → Setup OPA → Setup Terraform → Plan → Extract Policies → OPA Eval
```

## Usage

### Run OPA tests locally

```sh
opa test policies/ -v
```

### Evaluate a single policy file

```sh
opa eval -i <policy.json> -d policies/ "data.iam.result" --format pretty
```

### Run Terraform plan and validate

```sh
cd terraform/
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
```

Then extract and evaluate (as the GitHub Action does):

```sh
# Extract IAM policies from plan
python3 -c "
import json, os
with open('terraform/tfplan.json') as f:
    plan = json.load(f)
os.makedirs('opa_inputs', exist_ok=True)
for rc in plan.get('resource_changes', []):
    if rc['type'] in ('aws_iam_policy', 'aws_iam_role_policy'):
        after = rc.get('change', {}).get('after', {})
        policy_doc = json.loads(after.get('policy', '{}'))
        if policy_doc.get('Statement'):
            filename = rc['address'].replace('.', '_') + '.json'
            with open(f'opa_inputs/{filename}', 'w') as out:
                json.dump(policy_doc, out, indent=2)
"

# Evaluate each policy
for f in opa_inputs/*.json; do
  opa eval -i "$f" -d policies/ "data.iam.result" --format pretty
done
```

## Security Rules

The rules in `policies/iam.rego` enforce:

- **Denied actions** — blocks privilege escalation (iam:\*, iam:CreateUser, etc.), SSO/identity manipulation, account-level destructive actions, and security control tampering
- **NotAction evasion** — detects `NotAction` with `Effect: Allow` that implicitly grants denied actions
- **PassRole scoping** — requires `iam:PassRole` to have a scoped Resource (not `*`) and a `iam:PassedToService` condition

Wildcard matching is bidirectional and case-insensitive, matching real IAM behavior.

## Adding Rules

Edit `_denied_actions` in `policies/iam.rego` to add action patterns. For rules needing more context, add a `deny_<name>` rule set and wire it into the `violations` collection. See `deny_passrole_unscoped` or `deny_notaction` for examples.

## Output

```json
{
  "permit": false,
  "violations": [
    "Statement[0]: action 'account:EnableRegion' matches denied pattern 'account:EnableRegion'"
  ]
}
```

## QDA Workflow Integration

This compliance gate runs automatically when an account owner submits a PR with new or modified custom role IAM policies. The PR is blocked if any statement violates organisational security rules.

## Experimental: Cedar Path

The `scripts/` directory contains experimental tooling for a Cedar-based approach where IAM statements are modelled as Cedar entities and evaluated via `cedar authorize`. This is a future exploration path alongside the current OPA implementation.
