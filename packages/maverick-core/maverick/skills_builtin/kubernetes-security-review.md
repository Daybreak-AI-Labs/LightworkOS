---
name: kubernetes-security-review
triggers:
  - kubernetes security
  - container hardening
  - k8s review
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews a Kubernetes/container deployment for security posture and produces a prioritized review that names concrete policy gaps (RBAC, network, admission, secrets) and workload hardening gaps (privilege, capabilities, image provenance), each mapped to a remediation. Output is a recommendation set, not an applied change.

# Steps

1. Collect the real inputs: manifests/Helm values, `PodSecurity`/admission config, RBAC bindings, NetworkPolicies, and cluster version. If any are missing, list what was reviewed vs. assumed — never infer a control that was not shown.
2. Check workload hardening against each manifest: `runAsNonRoot`, `readOnlyRootFilesystem`, dropped capabilities, no `privileged`/`hostPID`/`hostNetwork`, resource limits, pinned image digests. Record the file and line for every finding.
3. Check cluster policy via knowledge_search against CIS Kubernetes Benchmark and Pod Security Standards baselines: namespace isolation, least-privilege RBAC (no cluster-admin wildcards), NetworkPolicy default-deny, secret encryption at rest. Cite the benchmark control ID.
4. Rank findings by severity (exploitability x blast radius), give a one-line fix per item, and report. State explicitly which controls could not be verified from the provided inputs and that a human owner must approve any cluster change.

# Notes

Output is wrong if it asserts a control's state without seeing the relevant manifest/config — mark those "unverified" rather than passing them. A clean manifest does not prove a clean cluster (admission webhooks, OPA/Kyverno policies, node config live elsewhere). This skill recommends only; it never applies RBAC, NetworkPolicy, or admission changes — those are staged for an operator. Do not use it as a compliance attestation; it is a review, not an audit sign-off.
