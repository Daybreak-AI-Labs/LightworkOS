resource "aws_ecs_cluster" "main" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${local.name}"
  retention_in_days = 14
}

resource "aws_ecs_task_definition" "app" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "app"
      # A digest pins the exact image; a tag follows re-pushes (variables.tf).
      image = (
        var.image_digest != ""
        ? "${aws_ecr_repository.app.repository_url}@${var.image_digest}"
        : "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
      )
      essential = true

      # ENTRYPOINT is `maverick`; run the dashboard bound to all interfaces
      # (allowed because MAVERICK_DASHBOARD_TOKEN is set below).
      command = ["dashboard", "--host", "0.0.0.0", "--port", tostring(var.container_port)]

      portMappings = [
        {
          containerPort = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = concat(
        [
          { name = "MAVERICK_WORLD_BACKEND", value = "postgres" },
          # Model-generated commands run in a separate executor, never in this
          # credential-bearing Fargate application task. Missing setup fails closed.
          { name = "MAVERICK_DEPLOYMENT_ISOLATION", value = "kubernetes" },
          { name = "MAVERICK_REQUIRE_CONTAINER_BACKEND", value = "1" },
          { name = "MAVERICK_EXECUTOR_NAMESPACE", value = var.executor_namespace },
          { name = "MAVERICK_EXECUTOR_IMAGE", value = var.executor_image },
          # Shared governed-record trust anchor: sha256 of the DECODED injected
          # at-rest key. crypto_at_rest.require_shared_deployment_key_identity
          # requires it for the Postgres (shared-authority) backend; without it
          # every governed-record read fails ("shared governed-record encryption
          # key identity is unavailable"), so the outcome-pilot admission gate
          # blocks every goal. Re-derive with `maverick shared-key-digest` if the
          # at-rest key ever rotates. The value is a one-way hash, not the key.
          { name = "MAVERICK_ENCRYPTION_KEY_DIGEST", value = var.encryption_key_digest },
        ],
        # Browser login via Auth0 (OIDC). Added only when an issuer is set, so
        # an unconfigured stack stays on static-token auth. redirect_uri and
        # audience are derived so there is one place to configure this.
        var.oidc_issuer == "" ? [] : [
          { name = "MAVERICK_OIDC_ENABLED", value = "1" },
          { name = "MAVERICK_OIDC_ISSUER", value = var.oidc_issuer },
          { name = "MAVERICK_OIDC_CLIENT_ID", value = var.oidc_client_id },
          { name = "MAVERICK_OIDC_AUDIENCE", value = var.oidc_client_id },
          { name = "MAVERICK_OIDC_REDIRECT_URI", value = "https://${var.domain_name}/auth/callback" },
          # The ID-token verifier needs the JWKS endpoint explicitly (it does not
          # derive it from the issuer). Standard OIDC discovery path off the issuer.
          { name = "MAVERICK_OIDC_JWKS_URI", value = "${trimsuffix(var.oidc_issuer, "/")}/.well-known/jwks.json" },
          # RP-initiated logout: without this the dashboard only clears its own
          # cookie and the IdP session silently signs the user straight back in.
          # Auth0's end-session endpoint lives at /oidc/logout on the issuer. The
          # app origin must also be in the IdP's post-logout allow-list.
          { name = "MAVERICK_OIDC_END_SESSION_ENDPOINT", value = "${trimsuffix(var.oidc_issuer, "/")}/oidc/logout" },
        ],
        var.dashboard_admins == "" ? [] : [
          { name = "MAVERICK_DASHBOARD_ADMINS", value = var.dashboard_admins },
        ],
        var.dashboard_invites ? [
          { name = "MAVERICK_DASHBOARD_INVITES", value = "1" },
        ] : [],
        var.flows_enabled ? [
          { name = "MAVERICK_FLOWS", value = "1" },
        ] : [],
        var.data_use_enabled ? [
          { name = "MAVERICK_DATA_USE_GOVERNANCE", value = "1" },
        ] : [],
        var.email_enabled ? [
          { name = "EMAIL_PROVIDER", value = "ses" },
          { name = "EMAIL_FROM", value = var.email_from },
          { name = "AWS_REGION", value = var.region },
        ] : [],
      )

      secrets = concat(
        [
          { name = "MAVERICK_PG_DSN", valueFrom = aws_secretsmanager_secret.pg_dsn.arn },
          { name = "MAVERICK_DASHBOARD_TOKEN", valueFrom = aws_secretsmanager_secret.dashboard_token.arn },
          { name = "ANTHROPIC_API_KEY", valueFrom = aws_secretsmanager_secret.anthropic_api_key.arn },
          { name = "MAVERICK_ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.at_rest_key.arn },
          # Receipt signing root for [consent_preferences.native_sdk]; the
          # config's receipt_key_secret_ref must name this variable.
          { name = "MAVERICK_CONSENT_RECEIPT_ROOT", valueFrom = aws_secretsmanager_secret.consent_receipt_root.arn },
        ],
        var.executor_kubeconfig_secret_arn == "" ? [] : [
          { name = "MAVERICK_EXECUTOR_KUBECONFIG_SECRET", valueFrom = var.executor_kubeconfig_secret_arn },
        ],
        var.oidc_issuer == "" ? [] : [
          { name = "MAVERICK_OIDC_CLIENT_SECRET", valueFrom = aws_secretsmanager_secret.oidc_client_secret.arn },
          { name = "MAVERICK_OIDC_SESSION_SECRET", valueFrom = aws_secretsmanager_secret.oidc_session_secret.arn },
        ],
      )

      # Durable ~/.maverick (tenant registry, roles, invites, saved flows,
      # dashboard config). The Dockerfile runs as uid/gid 1000; the EFS access
      # point pins the same identity so the non-root process can write.
      mountPoints = [
        { sourceVolume = "state", containerPath = "/home/maverick/.maverick", readOnly = false },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "app"
        }
      }
    }
  ])

  volume {
    name = "state"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.state.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.state.id
        iam             = "DISABLED"
      }
    }
  }

  # Keep superseded revisions registered so a rollback is one `update-service`
  # away instead of "TaskDefinition is inactive".
  skip_destroy = true

  lifecycle {
    precondition {
      condition     = var.executor_kubeconfig_secret_arn != "" && can(regex("@sha256:[a-f0-9]{64}$", var.executor_image))
      error_message = "Provision and qualify the separate Kubernetes executor first: set executor_kubeconfig_secret_arn and a digest-pinned executor_image. See deploy/aws/EXECUTOR.md."
    }
  }
}

resource "aws_ecs_service" "app" {
  name            = local.name
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # Stop-then-start, deliberately. The kernel holds an exclusive control-plane
  # lock on the data root (control_plane_lease.py) so exactly one writer ever
  # touches the hash-chained ledgers under ~/.maverick. With that root on EFS a
  # rolling deploy is impossible: the new task sees the old task's live lock and
  # refuses to start (observed: "ControlPlaneBusy ... Exactly one may write this
  # data root", rolled back by the circuit breaker). A deploy therefore has a
  # short gap while the old task stops and the new one passes health checks;
  # the circuit breaker restores the previous task definition if the new one
  # fails to start.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  platform_version                   = "1.4.0"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    # Public subnets with a public IP so the task can reach ECR / Secrets
    # Manager / the provider API without a NAT gateway. Inbound is still
    # restricted to the ALB security group.
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = var.container_port
  }

  # Let the app come up before the health check starts failing the task.
  health_check_grace_period_seconds = 120

  depends_on = [aws_lb_listener.http]

  lifecycle {
    ignore_changes = [desired_count]
  }
}
