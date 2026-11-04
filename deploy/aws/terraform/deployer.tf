# Deploy identity for routine deploys and CI: an IAM user whose access key lives
# in the deploying tool's environment settings, so routine deploys do not run as
# the account root through browser logins that expire every few hours.
#
# This credential deploys the already bootstrapped stack. IAM identities and
# policies, including this user's boundary, are changed only by a separate
# administrator apply. The access key is created and rotated outside Terraform.
resource "aws_iam_user" "deployer" {
  name                 = "${local.name}-deployer"
  permissions_boundary = aws_iam_policy.deployer.arn
  tags                 = { Purpose = "Lightwork prod deploys (Terraform, CodeBuild, ECS)" }
}

data "aws_iam_policy_document" "deployer" {
  # A same-account role trust policy can grant AssumeRole directly to a user.
  # Keep that route closed even if an unrelated trust policy changes later.
  statement {
    sid       = "NeverAssumeRole"
    effect    = "Deny"
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
  }

  # Read-only discovery Terraform and the CLI need everywhere.
  statement {
    sid = "Describe"
    actions = [
      "ec2:Describe*", "elasticloadbalancing:Describe*", "rds:Describe*", "rds:ListTagsForResource",
      "elasticfilesystem:Describe*", "ecs:Describe*", "ecs:List*", "ecr:Describe*", "ecr:List*",
      "ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
      "logs:Describe*", "logs:Get*", "logs:FilterLogEvents", "codebuild:BatchGet*", "codebuild:List*",
      "acm:Describe*", "acm:List*", "iam:Get*", "iam:List*", "sts:GetCallerIdentity",
      "secretsmanager:ListSecrets", "s3:ListAllMyBuckets", "ses:Get*", "ses:List*",
    ]
    resources = ["*"]
  }

  # Terraform state.
  statement {
    sid     = "State"
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketLocation"]
    resources = [
      "arn:aws:s3:::lightwork-tfstate-${data.aws_caller_identity.current.account_id}",
      "arn:aws:s3:::lightwork-tfstate-${data.aws_caller_identity.current.account_id}/*",
    ]
  }

  # Build source upload and the image build.
  statement {
    sid       = "Build"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.build.arn, "${aws_s3_bucket.build.arn}/*"]
  }
  statement {
    sid       = "CodeBuild"
    actions   = ["codebuild:*"]
    resources = [aws_codebuild_project.image.arn]
  }
  statement {
    sid       = "Ecr"
    actions   = ["ecr:*"]
    resources = [aws_ecr_repository.app.arn]
  }

  # Runtime writes are confined to this cluster, service, the stack's task
  # families (the app and its database and file-system maintenance tasks) and
  # their tasks. Read-only ECS discovery remains in Describe above.
  statement {
    sid     = "Ecs"
    actions = ["ecs:*"]
    resources = [
      "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:cluster/${local.name}",
      "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:service/${local.name}/${local.name}",
      "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task-definition/${local.name}:*",
      "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task-definition/${local.name}-*:*",
      "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${local.name}/*",
    ]
  }
  # AWS documents no resource-level permission for registering a task
  # definition, so no ARN above can allow it. Without this statement every apply
  # that publishes a new revision is denied. The task and execution roles a
  # revision may name stay limited to the fixed roles in PassEcsRoles below.
  statement {
    sid       = "EcsRegisterTaskDefinition"
    actions   = ["ecs:RegisterTaskDefinition"]
    resources = ["*"]
  }
  statement {
    sid     = "Logs"
    actions = ["logs:*"]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${local.name}*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/${local.name}*",
    ]
  }

  # Network, load balancer, database, state volume, certificates, email.
  # Infrastructure the stack creates has no ARN before it exists, so these
  # actions cannot be resource-scoped; they are bound to the deploy region
  # instead (every resource, including the ALB certificate and SES, lives in
  # the one region), and the data stores are protected by the Deny below.
  statement {
    sid = "Infra"
    actions = [
      "ec2:*Vpc*", "ec2:*Subnet*", "ec2:*RouteTable*", "ec2:*Route", "ec2:*InternetGateway*",
      "ec2:*SecurityGroup*", "ec2:*NetworkInterface*", "ec2:*Address*", "ec2:CreateTags", "ec2:DeleteTags",
      "ec2:ModifyVpcAttribute", "elasticloadbalancing:*", "rds:*", "elasticfilesystem:*", "acm:*", "ses:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [data.aws_region.current.name]
    }
  }

  # The deploy identity creates and changes the database and the state
  # volume but can never delete them or their backups: retiring either is a
  # separately reviewed operation under a different identity
  # (README.md, "Database protection on an existing deployment"). A Deny
  # wins over every Allow above, including rds:* and elasticfilesystem:*.
  statement {
    sid    = "NeverDeleteDataStores"
    effect = "Deny"
    actions = [
      "rds:DeleteDBInstance", "rds:DeleteDBCluster",
      "rds:DeleteDBSnapshot", "rds:DeleteDBClusterSnapshot",
      "elasticfilesystem:DeleteFileSystem",
    ]
    resources = ["*"]
  }

  # This stack's secrets only.
  statement {
    sid       = "Secrets"
    actions   = ["secretsmanager:*"]
    resources = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${local.name}/*"]
  }

  # Only hand the three fixed, separately administered roles to their services.
  # No Create/Put/Attach/PolicyVersion/User/Role IAM writes are granted: a CI
  # credential must never edit its own policy or mint an administrator role.
  statement {
    sid     = "PassEcsRoles"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-task-exec",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-task",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
  statement {
    sid       = "PassCodeBuildRole"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-codebuild"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "deployer" {
  name   = "${local.name}-deployer"
  policy = data.aws_iam_policy_document.deployer.json
}

resource "aws_iam_user_policy_attachment" "deployer" {
  user       = aws_iam_user.deployer.name
  policy_arn = aws_iam_policy.deployer.arn
}
