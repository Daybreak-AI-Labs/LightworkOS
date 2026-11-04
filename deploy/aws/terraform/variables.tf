variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-2"
}

variable "aws_profile" {
  description = "Local AWS CLI profile used by Terraform (authenticated via `aws login`)."
  type        = string
  default     = "lightwork"
}

variable "project" {
  description = "Short name used to prefix resources."
  type        = string
  default     = "lightwork"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "container_port" {
  description = "Port the maverick dashboard listens on inside the container."
  type        = number
  default     = 8765
}

variable "domain_name" {
  description = "Custom domain served over HTTPS (ACM cert + ALB 443 listener). Empty disables the cert/listener and leaves the stack HTTP-only on the ALB DNS name. DNS for this name is managed in Cloudflare, not Route 53."
  type        = string
}

variable "health_check_path" {
  description = "ALB target-group health check path. /livez answers 200 as soon as the process accepts HTTP (liveness only); /readyz runs the deep dependency checks and returns 503 while a dependency is down; because the ECS service uses this health check, ECS would stop and replace the tasks for as long as the dependency stays down."
  type        = string
  default     = "/livez"
}

# ---- OIDC browser login (Auth0) ----
# Empty issuer disables the whole OIDC block (the dashboard stays on static-token
# auth only). Set all three to turn on "Sign in" via Auth0. The client secret is
# NOT a variable -- it is written straight into Secrets Manager out-of-band.
variable "oidc_issuer" {
  description = "OIDC issuer URL, e.g. https://dev-abc123.us.auth0.com/ (trailing slash). Empty disables browser login."
  type        = string
  default     = ""
}

variable "oidc_client_id" {
  description = "OIDC application client ID (Auth0 application). Also used as the ID-token audience."
  type        = string
  default     = ""
}

variable "dashboard_admins" {
  description = "Comma-separated break-glass admin principals, e.g. user:auth0|abc123. These bypass all scoping. Set after first login once the principal's sub is known."
  type        = string
  default     = ""
}

variable "email_enabled" {
  description = "Wire the platform mailer into the task so invite emails send via the Amazon SES API using the task role (no stored SMTP credential). Requires the SES domain identity to be verified and the task role to have ses:SendEmail (see iam.tf)."
  type        = bool
  default     = false
}

variable "email_from" {
  description = "From address for platform emails (must be a verified SES identity, e.g. on the verified domain)."
  type        = string
  default     = ""
}

variable "dashboard_invites" {
  description = "Enable the dashboard's invite-by-email flow (the /users 'Invite someone by email' form and /auth/invite routes). With OIDC on, accepting an invite signs the invitee in via the IdP and binds their invited role."
  type        = bool
  default     = false
}

variable "flows_enabled" {
  description = "Turn on the flow engine (Flows designer Save/Publish/Run and the /api/v1/flows routes) by setting MAVERICK_FLOWS=1 on the task. Off by default in the product. Saved flows live under the task's data dir, so without persistent storage they do not survive a redeploy."
  type        = bool
  default     = false
}

variable "data_use_enabled" {
  description = "Turn on the Data Use Governance module by setting MAVERICK_DATA_USE_GOVERNANCE=1 on the task (env-first, like flows_enabled). Off by default in the product."
  type        = bool
  default     = false
}

variable "restrict_ingress_to_cloudflare" {
  description = "When true, the ALB only accepts traffic from Cloudflare's published IP ranges. Set this when the domain is proxied through Cloudflare (e.g. fronted by Cloudflare Access) so the public cannot bypass the edge by hitting the ALB directly. When false, the ALB is open to the internet."
  type        = bool
  default     = false
}

# Cloudflare's published edge ranges (https://api.cloudflare.com/client/v4/ips).
# Only consulted when restrict_ingress_to_cloudflare = true. Refresh if Cloudflare
# publishes new ranges.
variable "cloudflare_ipv4_cidrs" {
  description = "Cloudflare IPv4 ranges allowlisted on the ALB when restrict_ingress_to_cloudflare is true."
  type        = list(string)
  default = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
  ]
}

variable "cloudflare_ipv6_cidrs" {
  description = "Cloudflare IPv6 ranges allowlisted on the ALB when restrict_ingress_to_cloudflare is true."
  type        = list(string)
  default = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
  ]
}

variable "desired_count" {
  description = "Number of Fargate tasks. The control plane is single-replica by design."
  type        = number
  default     = 1
}

variable "task_cpu" {
  description = "Fargate task CPU units (1024 = 1 vCPU)."
  type        = string
  default     = "1024"
}

variable "task_memory" {
  description = "Fargate task memory (MiB)."
  type        = string
  default     = "2048"
}

variable "image_tag" {
  description = "ECR image tag the service runs. A tag can be re-pushed (the repository is MUTABLE), so a running service follows whatever `latest` points at on its next task start; set image_digest to pin the exact image."
  type        = string
  default     = "latest"
}

variable "image_digest" {
  description = "Optional sha256 digest of the image to run (sha256:<64 hex>). When set, the task definition names repository@digest, so the service runs exactly that image until the digest is changed here, whatever is pushed to image_tag later. Read it after a build with `aws ecr describe-images --repository-name <repo> --image-ids imageTag=<image_tag> --query 'imageDetails[0].imageDigest'`. Empty runs image_tag."
  type        = string
  default     = ""

  validation {
    condition     = var.image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be empty or sha256:<64 hex characters>."
  }
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage (GB)."
  type        = number
  default     = 20
}

variable "db_name" {
  description = "Initial Postgres database name."
  type        = string
  default     = "maverick"
}

variable "db_username" {
  description = "Postgres master username."
  type        = string
  default     = "maverick"
}

variable "encryption_key_digest" {
  description = "SHA-256 identity of the shared at-rest key, supplied by the deployment operator."
  type      = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.encryption_key_digest))
    error_message = "encryption_key_digest must be sha256: followed by the lowercase digest of the decoded at-rest key."
  }
}
