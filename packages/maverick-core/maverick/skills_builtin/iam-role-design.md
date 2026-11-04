---
name: iam-role-design
triggers:
  - design an IAM role
  - build a least-privilege permission set
  - create a permission set
tools_needed:
  - knowledge_search
---
# What this skill does

Designs least-privilege IAM roles or permission sets for a job function: maps the function's real tasks to the minimum permissions needed, structures them into reusable roles, and enforces separation-of-duties constraints. Output is a draft role definition package an identity owner reviews before provisioning.

# Steps

1. Gather the job function's actual responsibilities, the target platform's permission model, and existing roles/SoD policy via `knowledge_search`. Reuse or extend an existing role where one fits rather than inventing a new one; cite the source for each requirement.
2. Enumerate the discrete tasks the function performs, then map each to the narrowest permission/action that enables it. Prefer read over write, scoped over wildcard, and resource-bounded over account-wide; record the task that justifies every permission granted.
3. Assemble permissions into one or more roles (or a permission set), grouping by duty so conflicting duties land in separate roles. Apply SoD rules from knowledge (e.g., requester cannot also approve; deployer cannot also audit) and flag any permission that would breach them.
4. Produce the role definition (name, scope, permission list with per-permission justification, SoD notes, intended assignees) and report it as a draft. Hand off to the identity owner for review and provisioning, stating assumptions about platform model and any permissions left out pending confirmation.

# Notes

Output is wrong if it grants wildcard/broad permissions for convenience, omits the justifying task for any permission, or ignores SoD constraints (a role that both spends and approves). Provisioning the role is the irreversible action and is staged for a human — this skill drafts and recommends only. Do not use to grant emergency access or to bypass an existing approval workflow. Mark any permission whose effect is unverified against the platform model rather than assuming it is safe.
