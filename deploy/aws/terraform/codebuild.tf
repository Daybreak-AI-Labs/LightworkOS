# Dedicated bucket for the build source archive (uploaded out-of-band before a
# build is started, then referenced by the CodeBuild project).
resource "aws_s3_bucket" "build" {
  bucket        = "${local.name}-build-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "build" {
  bucket                  = aws_s3_bucket.build.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_log_group" "codebuild" {
  name              = "/aws/codebuild/${local.name}"
  retention_in_days = 14
}

# Builds deploy/docker/Dockerfile from the uploaded source zip and pushes to
# ECR. Privileged mode is required to run the Docker daemon inside the build.
resource "aws_codebuild_project" "image" {
  name         = local.name
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = data.aws_region.current.name
    }
    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
    }
    environment_variable {
      name  = "ECR_REPO"
      value = aws_ecr_repository.app.repository_url
    }
    environment_variable {
      name  = "IMAGE_TAG"
      value = var.image_tag
    }
  }

  source {
    type      = "S3"
    location  = "${aws_s3_bucket.build.bucket}/source.zip"
    buildspec = <<-EOT
      version: 0.2
      phases:
        pre_build:
          commands:
            - echo Logging in to ECR...
            - aws ecr get-login-password --region "$AWS_DEFAULT_REGION" | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com"
        build:
          commands:
            - echo Building image...
            - docker build -f deploy/docker/Dockerfile -t "$ECR_REPO:$IMAGE_TAG" .
        post_build:
          commands:
            - echo Pushing image...
            - docker push "$ECR_REPO:$IMAGE_TAG"
    EOT
  }

  logs_config {
    cloudwatch_logs {
      group_name = aws_cloudwatch_log_group.codebuild.name
    }
  }

  tags = { Name = local.name }
}
