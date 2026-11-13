# Reference architectures

Self-hostable deployment blueprints for the governed Lightwork runtime. Every
one runs the dashboard + control plane from the Lightwork container image and
keeps state on a persistent volume; secrets come from the platform's secret
store, never the image. Pick the one that matches where you already run things.
The manifests are in this repository under `deploy/reference-architectures/`.

> All four use the image built from `deploy/docker/Dockerfile`. No prebuilt
> image is published yet: Fly.io and Railway build it from the repository, and
> for Kubernetes and ECS you build it and push it to your own registry. All four
> expose the dashboard on port **8765** and use auth-exempt **`/readyz`**
> readiness and **`/livez`** liveness probes where the platform supports both.
> Keep exactly **one** dashboard/control-plane instance, including with
> `[world_model] backend = "postgres"`; Postgres and the queue let you scale the
> separate `maverick worker` tier, not the web tier.

| Platform | Manifest | State | Secrets |
|---|---|---|---|
| Kubernetes | `kubernetes/maverick.yaml` | PVC (`ReadWriteOnce`) | `Secret` → `envFrom` |
| AWS ECS (Fargate) | `ecs/task-definition.json` | EFS volume | Secrets Manager → `secrets` |
| Fly.io | `flyio/fly.toml` | Fly volume at `/state` | `fly secrets set` |
| Railway | `railway/railway.json` | Railway volume at `/state` | service variables |

## Kubernetes

Replace `REGISTRY/maverick:0.1.7` in the manifest with your built image, pinned
to an immutable tag or digest. Create the `maverick-secrets` Secret first; the
manifest's header comment shows the commands. The dashboard binds `0.0.0.0` in
this blueprint, so the Secret must include `MAVERICK_DASHBOARD_TOKEN`. Then:

```bash
kubectl apply -f deploy/reference-architectures/kubernetes/maverick.yaml
kubectl port-forward svc/maverick 8765:80
```

The manifest creates a PersistentVolumeClaim, a single-replica Deployment and a
ClusterIP Service in the current namespace (pass `-n <namespace>` to every
command, including the Secret creation, to use another). The pod runs as
non-root, is readiness-gated on `/readyz` and liveness-gated on `/livez`, and
keeps state on a 10Gi PVC. Source the Secret's values from your secret manager
(External Secrets Operator / Sealed Secrets), and add an Ingress/Gateway for TLS
termination.

## AWS ECS (Fargate)

```bash
aws ecs register-task-definition \
  --cli-input-json file://deploy/reference-architectures/ecs/task-definition.json
```

Fill in `ACCOUNT_ID`, `REGION`, the EFS `fileSystemId`, and the Secrets Manager
ARNs, then create a service behind an ALB whose target group points at
container port 8765. The task-level liveness check uses `/livez`; configure the
ALB target group's readiness check on `/readyz`.

## Fly.io

```bash
fly launch --copy-config --no-deploy
fly volumes create maverick_state --size 10
fly secrets set ANTHROPIC_API_KEY=... MAVERICK_DASHBOARD_TOKEN=...
fly deploy
```

`force_https` is on; `min_machines_running = 1` keeps the single writer alive,
and the service readiness check uses `/readyz`.

## Railway

Create a project from the repo, add a Volume mounted at `/state`, set
`ANTHROPIC_API_KEY` and `MAVERICK_DASHBOARD_TOKEN` in the service variables, and
deploy. The shipped start command binds the dashboard to port 8765 and
health-checks `/readyz`; configure Railway's target port accordingly.

## Scaling to multi-tenant / multi-worker

These blueprints use one dashboard/control-plane node. To add processing
capacity, see the [enterprise architecture](enterprise/architecture.md): the Postgres
world-model backend (tenant isolation + migrations), the `QueueDispatcher`
(arq) worker pool, per-tenant KMS/egress, and the operator console. Once
Postgres + queue are configured, keep one web/control-plane replica (`maverick
dashboard`) and scale only the separate worker tier (`maverick worker`).
