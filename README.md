
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

## Cedar IAM Policy Validation — Repository Structure

```
github-repo/
├── .github/
│   └── workflows/
│       └── iam-policy-check.yml          # The GitHub Action
│
├── cedar/
│   ├── schema.cedarschema                # Cedar schema definition
│   └── rules.cedar                       # Your compliance rules (forbid policies)
│
├── scripts/
│   ├── iam_to_cedar_entities.py          # Converts tfplan.json → entities.json
│   └── run_cedar_checks.py              # Runs cedar authorize per statement
│
├── terraform/                            # Terraform IAM policies & roles
│   ├── main.tf                          # The IAM policies & roles
│   ├── variables.tf                     # (optional) extracted variables
│   ├── outputs.tf                       # (optional) extracted outputs
│   └── backend.tf                       # (optional) state backend config
│
└── README.md
```

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
