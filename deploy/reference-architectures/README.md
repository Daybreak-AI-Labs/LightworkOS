# Reference architectures

Self-hosted deployment blueprints for the Lightwork runtime, one per platform.
Each directory is a minimal, working starting point — copy it, fill in the
placeholders (image registry, secrets), and grow it to your environment.

| Platform | Files | Shape |
|---|---|---|
| [Kubernetes](./kubernetes/) | `maverick.yaml` | Deployment + Service + Secret + PVC; dashboard on `:8765` behind a ClusterIP |
| [AWS ECS (Fargate)](./ecs/) | `task-definition.json` | Single-task service; state on EFS; secrets from SSM |
| [Fly.io](./flyio/) | `fly.toml` | One machine + volume; dashboard service with health checks |
| [Railway](./railway/) | `railway.json` | Dockerfile build; volume mount; env-driven config |
| [Demo cluster](./demo-cluster/) | `docker-compose.yml`, `k8s.yaml` | Public read-only demo: seeded data + nginx deny-proxy (GET/HEAD only) in front of a token-protected dashboard |

Shared assumptions:

- **Image**: built from [`deploy/docker/Dockerfile`](../docker/Dockerfile)
  (`docker build -f deploy/docker/Dockerfile -t <registry>/maverick:latest .`).
- **State**: everything lives under `/home/maverick/.maverick` — mount a persistent
  volume there or runs/audit/config vanish on redeploy.
- **Secrets**: provider API keys (e.g. `ANTHROPIC_API_KEY`) come from the
  platform's secret store, never baked into the image.
- **Surface**: the long-running process is `maverick dashboard --host 0.0.0.0
  --port 8765` (web UI + API + webhooks). One-shot goals run as jobs/exec:
  `maverick start "..."`.
- **Self-hosted**: none of these require a hosted Lightwork
  service; they run entirely in your account.
