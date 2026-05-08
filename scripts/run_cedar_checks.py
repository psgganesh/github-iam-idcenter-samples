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
            print(f"FAILED: {stmt_id}")
        else:
            print(f"PASSED: {stmt_id}")

    if failures:
        print(f"{len(failures)} policy statement(s) violate compliance rules.")
        sys.exit(1)
    else:
        print(f"All {len(statements)} statement(s) are compliant.")
        sys.exit(0)

if __name__ == "__main__":
    main()
