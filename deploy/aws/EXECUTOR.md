# Separate execution for the Fargate application

The application task holds database, model, encryption and dashboard credentials.
Fargate isolates that task from its host; it does not isolate a local child
process from the application inside the same task. Production model commands
therefore require a separate worker-only Kubernetes executor.

Terraform now requires `executor_kubeconfig_secret_arn` and a digest-pinned
`executor_image` before publishing an application task definition. The runtime
pins execution to Kubernetes, disables worker networking, clears extra kubectl
arguments and rejects local/SSH/backend overrides. It never installs a Docker
socket in the application task. The image includes a checksum-verified kubectl
client (build argument `KUBECTL_VERSION`, currently v1.36.4).

## Provision before rollout

1. Select an existing/new Kubernetes cluster and qualify its worker isolation,
   restricted Pod Security admission and NetworkPolicy-enforcing CNI. Kubernetes
   API policy objects alone do not prove packet filtering. Keep the kubectl
   client within the cluster's supported version-skew window; see the official
   [client installation guidance](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/).
2. Review and apply `executor-namespace.yaml`. Adjust all namespace fields
   together if needed. Use a dedicated namespace with no application secrets,
   databases, shared host mounts or other application services. Do not add egress
   allow policies to this namespace. The role can create/exec/delete pods and
   inspect NetworkPolicy; it cannot list secrets or change cluster policy.
3. Provision a credential for `lightwork-controller` only. Store its flattened,
   single-context **JSON** kubeconfig in AWS Secrets Manager. Embed the cluster
   CA and token or client certificate/key. Command-based credential plugins,
   local credential file references, proxies and insecure TLS are refused.
   Do not use a cluster-admin kubeconfig. Establish credential rotation before
   token/certificate expiry; restarting the task loads a newly injected secret.
4. Build and qualify a Linux worker image containing `sh` and `tar`, with no
   application settings/keys. The worker image must be accessible to the cluster
   and referenced by `@sha256:…`. Configure the separate document worker image
   if native OCR/calculation is enabled; see `docs/document-processing.md`.
5. Set Terraform variables, then review its plan before applying:

   ```hcl
   executor_kubeconfig_secret_arn = "arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME" # pragma: allowlist secret -- placeholder ARN
   executor_namespace             = "lightwork-execution"
   executor_image                 = "REGISTRY/WORKER@sha256:REVIEWED_DIGEST"
   ```

The task execution role receives `GetSecretValue` for that exact secret ARN. If
the secret uses a customer-managed KMS key, grant the task execution role the
necessary scoped decrypt permission through the key policy; this module does
not add broad KMS permissions. The application must be able to reach the cluster
API over TLS. Workers receive an empty workspace volume and no service-account
token; the kubeconfig stays in private application control-plane storage.

## Required acceptance evidence

Before production use, exercise a real goal that creates, changes, renames and deletes
workspace files; verify the resulting local files. Exercise command timeout,
lost export connectivity, concurrent local edits and the recovery procedure in
`docs/sandbox-kubernetes-recovery.md`. Confirm that a worker cannot read app
credentials, contact cloud metadata, reach the Internet or other tenants, mount
host storage or create a privileged pod. Record image digests, cluster/CNI/runtime
versions, identities and results. Run the actual third-party integrations
separately with authorized test accounts.

This repository supplies the application contract, namespace policy and local
regression coverage. It does **not** create/qualify an external cluster, populate
Secrets Manager, rotate credentials or apply an AWS deployment automatically.
Deployment is incomplete until those external steps and acceptance checks pass.
The local Firecracker scaffold remains unsupported; selecting it does not satisfy
this executor contract.
