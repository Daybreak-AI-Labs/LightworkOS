# One-off maintenance task: a Postgres client in the app's network with the
# app's database DSN. Never part of the service; run on demand with
# `aws ecs run-task` and a SQL override, e.g. to remove rows sealed under a
# lost at-rest key. Logs land next to the app's under the "dbtask" prefix.
resource "aws_ecs_task_definition" "dbtask" {
  family                   = "${local.name}-dbtask"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    {
      name       = "psql"
      image      = "public.ecr.aws/docker/library/postgres:16-alpine"
      essential  = true
      entryPoint = ["sh", "-c"]
      command    = ["psql \"$PGDSN\" -v ON_ERROR_STOP=1 -X -c \"$SQL\""]
      secrets = [
        { name = "PGDSN", valueFrom = aws_secretsmanager_secret.pg_dsn.arn },
      ]
      environment = [
        { name = "SQL", value = "SELECT 1" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "dbtask"
        }
      }
    }
  ])
}
