---
name: privileged-access-review
triggers:
  - review privileged access
  - run a PAM review
  - audit admin accounts
tools_needed:
  - sql_query
---
# What this skill does

Reviews privileged, admin, and service accounts against least-privilege expectations: enumerates who holds elevated rights, checks for standing access, shared credentials, and unused admin grants, and produces a findings list with right-sizing recommendations. Output is a review report; revocations are staged for an account owner.

# Steps

1. Query the elevated-access population with `sql_query`: accounts with admin/root/superuser roles, group memberships granting elevation, service accounts, MFA status, last-login, and grant date. State the as-of timestamp.
2. Classify each: standing vs just-in-time, human vs service, shared vs individual. Flag standing admin where JIT is expected, shared/generic admin logins, admins without MFA, and elevated grants unused within the policy window.
3. For each finding, record the account, the elevated right, evidence (last-used, MFA flag, owner), severity, and a least-privilege recommendation (remove standing access, move to JIT, split shared account, add MFA, or revoke if dormant). Do not recommend certify for any dormant or shared privileged account.
4. Report the findings ranked by severity and hand the revoke/right-size actions to the account owner for execution, stating assumptions about which accounts are service vs human and any accounts whose owner could not be determined.

# Notes

Output is wrong if a finding lacks evidence from the query, if service accounts are treated as human (breaking automation when revoked), or if the data as-of date is missing. Changing or disabling a privileged account is the irreversible action and is staged for a human — never auto-revoke admin or service credentials. Do not use for routine end-user entitlement reviews (use access-review-campaign) or for break-glass accounts governed by a separate process. Cite the query for every account listed.
