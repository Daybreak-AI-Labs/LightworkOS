# CloudWatch alarms for the single-replica deployment, all notifying one SNS
# topic. Without them a degraded stack is noticed only by its users: the EFS
# state volume once ran out of burst credits for a day, was throttled to its
# baseline throughput and made every signed-in page take seconds, and nothing
# reported it. Thresholds are variables (variables.tf, "Alarms"); each alarm's
# description says what it means and what to do first.

locals {
  alarm_actions = [aws_sns_topic.alarms.arn]

  alb_dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.app.arn_suffix
  }
  ecs_dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.app.name
  }
  efs_dimensions = { FileSystemId = aws_efs_file_system.state.id }
  rds_dimensions = { DBInstanceIdentifier = aws_db_instance.main.identifier }

  # Burst credits only limit a file system in bursting mode (the AWS default
  # when throughput_mode is unset); in provisioned or elastic mode the
  # throughput-utilisation alarm below covers the same failure.
  efs_bursting = coalesce(aws_efs_file_system.state.throughput_mode, "bursting") == "bursting"

  # A 5xx rate over a handful of requests is noise; below this many requests in
  # five minutes the target 5xx rate alarm treats the window as healthy.
  target_5xx_min_requests = 20
}

# Unencrypted on purpose: CloudWatch can publish to an encrypted topic only
# through a customer managed KMS key whose policy admits CloudWatch, and the
# messages carry alarm names and metric values, not application data.
resource "aws_sns_topic" "alarms" {
  name = "${local.name}-alarms"
  tags = { Name = "${local.name}-alarms" }
}

# AWS emails a confirmation link to this address; no alarm is delivered until
# the recipient opens it and confirms the subscription.
resource "aws_sns_topic_subscription" "alarm_email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---- Load balancer ----

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${local.name}-alb-5xx"
  alarm_description   = "The load balancer itself answered with 5xx errors (502, 503 or 504): it could not reach a healthy app task, or the app timed out or dropped the connection. A deploy stops the old task before starting the new one, so a burst right after a deploy that clears on its own is expected. Otherwise check the ECS service events, the unhealthy-target alarm and the app logs in /ecs/${local.name}."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  dimensions          = { LoadBalancer = aws_lb.main.arn_suffix }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_alb_5xx_count
  treat_missing_data  = "notBreaching" # no 5xx responses publishes no data
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "target_5xx_rate" {
  alarm_name          = "${local.name}-target-5xx-rate"
  alarm_description   = "More than ${var.alarm_target_5xx_percent}% of requests the app answered in five minutes were server errors (5xx) from the app itself. Users are seeing failures. Check the app logs in /ecs/${local.name} for the failing routes and whether a recent deploy or a dependency (database, state volume, model provider) is the cause."
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_target_5xx_percent
  treat_missing_data  = "notBreaching" # no traffic is not an error

  metric_query {
    id          = "rate"
    expression  = "IF(requests >= ${local.target_5xx_min_requests}, 100 * FILL(errors, 0) / requests, 0)"
    label       = "Target 5xx (% of requests)"
    return_data = true
  }

  metric_query {
    id = "errors"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_Target_5XX_Count"
      dimensions  = local.alb_dimensions
      stat        = "Sum"
      period      = 300
    }
  }

  metric_query {
    id = "requests"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "RequestCount"
      dimensions  = local.alb_dimensions
      stat        = "Sum"
      period      = 300
    }
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  alarm_name          = "${local.name}-unhealthy-targets"
  alarm_description   = "The load balancer marks the app task unhealthy: it failed ${aws_lb_target_group.app.health_check[0].unhealthy_threshold} health checks on ${var.health_check_path} in a row. With a single replica the site is down or about to be replaced. ECS normally replaces the task by itself; if this does not clear within a few minutes, check the ECS service events and the app logs in /ecs/${local.name}."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = local.alb_dimensions
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  # No task at all is not "unhealthy"; the running-task alarm reports that.
  treat_missing_data = "notBreaching"
  alarm_actions      = local.alarm_actions
  ok_actions         = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "target_response_time_p95" {
  alarm_name          = "${local.name}-response-time-p95"
  alarm_description   = "The slowest 5% of requests took longer than ${var.alarm_target_response_p95_seconds} s for 15 minutes. Pages feel slow to users. Check the state volume (EFS throughput and burst-credit alarms), the database CPU and memory alarms and the app task CPU and memory alarms; the earlier incident with this symptom was the state volume running out of burst credits."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "TargetResponseTime"
  dimensions          = local.alb_dimensions
  extended_statistic  = "p95"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_target_response_p95_seconds
  treat_missing_data  = "notBreaching" # no requests, nothing slow
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# ---- ECS service ----

# Container Insights (enabled on the cluster in ecs.tf) publishes the running
# and desired task counts. Deploys are stop-then-start (ecs.tf), so a deploy
# leaves the service short for a few minutes by design: the alarm needs five
# short minutes out of ten. No data at all means the service or its metrics
# are gone, which is treated as short.
resource "aws_cloudwatch_metric_alarm" "ecs_running_tasks" {
  alarm_name          = "${local.name}-ecs-running-below-desired"
  alarm_description   = "Fewer app tasks are running than the service wants, for at least 5 of the last 10 minutes. With a single replica that means the site is down. Check the ECS service events (failed image pull, missing secret, failing health checks, a rolled-back deploy) and the app logs in /ecs/${local.name}."
  evaluation_periods  = 10
  datapoints_to_alarm = 5
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "breaching"

  metric_query {
    id          = "shortfall"
    expression  = "desired - running"
    label       = "Tasks short of desired"
    return_data = true
  }

  metric_query {
    id = "running"
    metric {
      namespace   = "ECS/ContainerInsights"
      metric_name = "RunningTaskCount"
      dimensions  = local.ecs_dimensions
      stat        = "Minimum"
      period      = 60
    }
  }

  metric_query {
    id = "desired"
    metric {
      namespace   = "ECS/ContainerInsights"
      metric_name = "DesiredTaskCount"
      dimensions  = local.ecs_dimensions
      stat        = "Maximum"
      period      = 60
    }
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "ecs_cpu_high" {
  alarm_name          = "${local.name}-ecs-cpu-high"
  alarm_description   = "The app task has used more than ${var.alarm_ecs_cpu_percent}% of its CPU for 15 minutes. Requests queue and pages slow down. Check what the app is doing in /ecs/${local.name}; if the load is legitimate, raise task_cpu (variables.tf) and apply."
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  dimensions          = local.ecs_dimensions
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_ecs_cpu_percent
  treat_missing_data  = "missing" # a missing task is the running-task alarm's job
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "ecs_memory_high" {
  alarm_name          = "${local.name}-ecs-memory-high"
  alarm_description   = "The app task has used more than ${var.alarm_ecs_memory_percent}% of its memory for 15 minutes. At 100% the container is killed and the site goes down until a new task starts. Check the app logs in /ecs/${local.name} for what is growing; if the usage is legitimate, raise task_memory (variables.tf) and apply."
  namespace           = "AWS/ECS"
  metric_name         = "MemoryUtilization"
  dimensions          = local.ecs_dimensions
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_ecs_memory_percent
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# ---- EFS state volume ----

resource "aws_cloudwatch_metric_alarm" "efs_burst_credits_low" {
  count               = local.efs_bursting ? 1 : 0
  alarm_name          = "${local.name}-efs-burst-credits-low"
  alarm_description   = "The state volume's burst credit balance is below ${var.alarm_efs_burst_credit_low_gib} GiB and falling. At zero, EFS throttles it to its small baseline throughput and every signed-in page takes seconds (this has happened). Switch the file system to provisioned or elastic throughput before the balance reaches zero."
  namespace           = "AWS/EFS"
  metric_name         = "BurstCreditBalance"
  dimensions          = local.efs_dimensions
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = var.alarm_efs_burst_credit_low_gib * 1073741824
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "efs_io_limit" {
  alarm_name          = "${local.name}-efs-io-limit"
  alarm_description   = "The state volume has been above ${var.alarm_efs_io_limit_percent}% of the General Purpose I/O limit for 15 minutes. File operations will start to queue and pages slow down. Look for a job or task doing heavy small-file I/O on ~/.maverick in /ecs/${local.name}."
  namespace           = "AWS/EFS"
  metric_name         = "PercentIOLimit"
  dimensions          = local.efs_dimensions
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_efs_io_limit_percent
  treat_missing_data  = "notBreaching" # an idle volume publishes no data
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# Metered throughput as a share of what EFS currently permits (the AWS EFS
# "percentage of permitted throughput utilization" metric math). It works in
# every throughput mode: in bursting mode PermittedThroughput falls to the
# baseline when credits run out, so this also catches the credit exhaustion.
resource "aws_cloudwatch_metric_alarm" "efs_throughput_utilisation" {
  alarm_name          = "${local.name}-efs-throughput-high"
  alarm_description   = "The state volume has used more than ${var.alarm_efs_throughput_percent}% of the throughput EFS permits it for 15 minutes. At 100% EFS throttles it and every signed-in page slows down. In bursting mode check the burst credit balance; in provisioned mode raise the provisioned throughput, or switch to elastic throughput."
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_efs_throughput_percent
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "utilisation"
    expression  = "100 * (FILL(metered, 0) / PERIOD(metered)) / permitted"
    label       = "Throughput utilisation (%)"
    return_data = true
  }

  metric_query {
    id = "metered"
    metric {
      namespace   = "AWS/EFS"
      metric_name = "MeteredIOBytes"
      dimensions  = local.efs_dimensions
      stat        = "Sum"
      period      = 300
    }
  }

  metric_query {
    id = "permitted"
    metric {
      namespace   = "AWS/EFS"
      metric_name = "PermittedThroughput"
      dimensions  = local.efs_dimensions
      stat        = "Average"
      period      = 300
    }
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}

# ---- RDS Postgres ----

resource "aws_cloudwatch_metric_alarm" "rds_cpu_high" {
  alarm_name          = "${local.name}-rds-cpu-high"
  alarm_description   = "The database has used more than ${var.alarm_rds_cpu_percent}% CPU for 15 minutes. Queries slow down and so does every page that reads the world model. Find the expensive queries in pg_stat_activity (the maintenance task in dbtask.tf); if the load is legitimate, move to a larger db_instance_class."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = local.rds_dimensions
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_rds_cpu_percent
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_free_storage_low" {
  alarm_name          = "${local.name}-rds-free-storage-low"
  alarm_description   = "The database has less than ${var.alarm_rds_free_storage_low_gib} GiB of free disk. Storage autoscaling should grow it up to max_allocated_storage (rds.tf); if it is already at that ceiling, raise it. A full disk stops all writes."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = local.rds_dimensions
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = var.alarm_rds_free_storage_low_gib * 1073741824
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_freeable_memory_low" {
  alarm_name          = "${local.name}-rds-freeable-memory-low"
  alarm_description   = "The database has had less than ${var.alarm_rds_freeable_memory_low_mib} MiB of free memory for 15 minutes. It will start swapping and slow down, and may restart. Check the connection count and long-running queries; if the load is legitimate, move to a larger db_instance_class."
  namespace           = "AWS/RDS"
  metric_name         = "FreeableMemory"
  dimensions          = local.rds_dimensions
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "LessThanThreshold"
  threshold           = var.alarm_rds_freeable_memory_low_mib * 1048576
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# Only burstable (db.t*) classes earn and spend CPU credits.
resource "aws_cloudwatch_metric_alarm" "rds_cpu_credits_low" {
  count               = startswith(var.db_instance_class, "db.t") ? 1 : 0
  alarm_name          = "${local.name}-rds-cpu-credits-low"
  alarm_description   = "The database's CPU credit balance is below ${var.alarm_rds_cpu_credit_low}. It has been using more CPU than its burstable class earns. RDS runs burstable classes in Unlimited mode, so it keeps bursting but the CPU above the baseline is billed as surplus credits. If this persists, move to a larger or non-burstable db_instance_class."
  namespace           = "AWS/RDS"
  metric_name         = "CPUCreditBalance"
  dimensions          = local.rds_dimensions
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = var.alarm_rds_cpu_credit_low
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_connections_high" {
  alarm_name          = "${local.name}-rds-connections-high"
  alarm_description   = "The database has more than ${var.alarm_rds_connections_high} open connections. Postgres refuses new connections at its max_connections limit, which on a small instance class is low, and the app then fails requests. Check for connection leaks or stuck maintenance tasks; restarting the app task releases its connections."
  namespace           = "AWS/RDS"
  metric_name         = "DatabaseConnections"
  dimensions          = local.rds_dimensions
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.alarm_rds_connections_high
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}
