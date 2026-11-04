---
name: infra-as-code-review
triggers:
  - review this terraform
  - iac review
  - check our infrastructure code
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Reviews infrastructure-as-code (Terraform, CloudFormation, Pulumi, Helm) for security misconfigurations, configuration drift, and module-design problems. Produces a findings report grouped by severity with file:line citations and concrete remediations, plus a drift check against documented intended state.

# Steps

1. Read the IaC files in scope (`read_file`) — enumerate providers, resources, modules, and variable/state references. Do not assume resources not present in the files.
2. Scan each resource for security issues against `knowledge_search` baselines: public ingress (0.0.0.0/0), unencrypted storage/volumes, plaintext or hardcoded secrets, over-broad IAM (`*` actions/resources), missing logging/versioning, and default credentials. Cite each finding by file and line.
3. Assess module hygiene: pinned provider/module versions, no hardcoded environment values, inputs validated, outputs minimal, no duplicated copy-paste blocks that should be a module. Flag drift risk where committed config diverges from documented intended state (lifecycle ignore_changes, manual console edits noted in knowledge).
4. Report findings grouped Critical/High/Medium/Low, each with file:line, the risk, and a remediation. State assumptions (e.g. unseen tfvars, remote state not inspected). Mark anything you could not verify as unverified — do NOT apply changes; recommend only.

# Notes

Output is wrong if it asserts a misconfiguration the files don't actually show (e.g. inferring an open security group from a variable name) — every finding must trace to a concrete line. Cannot detect drift from live cloud state without plan/apply output; flag that gap explicitly rather than guessing. This skill reviews and recommends — it never runs `terraform apply` or mutates infrastructure; a human approves and applies. Not for greenfield authoring (use a scaffolding skill) or for live incident remediation.
