data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  secret_arns = concat([
    aws_secretsmanager_secret.pg_dsn.arn,
    aws_secretsmanager_secret.dashboard_token.arn,
    aws_secretsmanager_secret.anthropic_api_key.arn,
    aws_secretsmanager_secret.oidc_session_secret.arn,
    aws_secretsmanager_secret.oidc_client_secret.arn,
    aws_secretsmanager_secret.at_rest_key.arn,
    aws_secretsmanager_secret.consent_receipt_root.arn,
  ], var.executor_kubeconfig_secret_arn == "" ? [] : [var.executor_kubeconfig_secret_arn])
}

# ---- ECS task execution role (pulls the image, writes logs, reads secrets) ----

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task_execution" {
  name               = "${local.name}-task-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "task_secrets" {
  statement {
    sid       = "ReadTaskSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.secret_arns
  }
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name   = "read-secrets"
  role   = aws_iam_role.task_execution.id
  policy = data.aws_iam_policy_document.task_secrets.json
}

# ---- ECS task role (the app's own runtime identity; minimal) ----

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

# The app sends platform email (invite links) through the Amazon SES API using
# this task role — no stored SMTP credential. Send-only; the verified identity
# (the SES identity you verified for your domain) is enforced by SES itself.
data "aws_iam_policy_document" "task_ses" {
  statement {
    sid       = "SESSend"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "task_ses" {
  name   = "ses-send"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_ses.json
}

# ---- CodeBuild role (build the image from S3 source, push to ECR, log) ----

data "aws_iam_policy_document" "codebuild_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "${local.name}-codebuild"
  assume_role_policy = data.aws_iam_policy_document.codebuild_assume.json
}

data "aws_iam_policy_document" "codebuild" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/${local.name}*"]
  }
  statement {
    sid       = "SourceBucket"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.build.arn, "${aws_s3_bucket.build.arn}/*"]
  }
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "EcrPush"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.app.arn]
  }
}

resource "aws_iam_role_policy" "codebuild" {
  name   = "codebuild"
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.codebuild.json
}
