provider "aws" {
  region = var.region

  # Credentials come from the environment. The `aws login` flow stores them
  # under a CLI-only mechanism the Terraform SDK cannot read, so callers export
  # them first:  eval "$(aws configure export-credentials --profile lightwork --format env)"

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
