# One-off maintenance task on the app's state volume: a shell with the same
# EFS access point the app mounts at /home/maverick/.maverick, so an operator
# can place or inspect files there (config.toml, the dashboard overlay, the
# tenant registry) without a shell into the running task. Never part of the
# service; run on demand with `aws ecs run-task` and a command override, e.g.
# `cd /home/maverick/.maverick && ls -la`. Logs land next to the app's under
# the "fstask" prefix. Same image as the DB task so nothing new is pulled.
resource "aws_ecs_task_definition" "fstask" {
  family                   = "${local.name}-fstask"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    {
      name       = "fs"
      image      = "public.ecr.aws/docker/library/postgres:16-alpine"
      essential  = true
      entryPoint = ["sh", "-c"]
      command    = ["ls -la /home/maverick/.maverick"]
      mountPoints = [
        { sourceVolume = "state", containerPath = "/home/maverick/.maverick", readOnly = false },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "fstask"
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
}
