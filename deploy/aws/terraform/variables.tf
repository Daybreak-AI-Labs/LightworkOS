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

variable "efs_throughput_mode" {
  description = "EFS throughput mode for the state volume: provisioned, elastic or bursting. Bursting gives a small volume only ~1 MiB/s once its credits run out."
  type        = string
  default     = "provisioned"

  validation {
    condition     = contains(["provisioned", "elastic", "bursting"], var.efs_throughput_mode)
    error_message = "efs_throughput_mode must be provisioned, elastic or bursting."
  }
}

variable "efs_provisioned_throughput_mibps" {
  description = "Provisioned EFS throughput in MiB/s when efs_throughput_mode is provisioned (billed per MiB/s-month)."
  type        = number
  default     = 10
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
  type        = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.encryption_key_digest))
    error_message = "encryption_key_digest must be sha256: followed by the lowercase digest of the decoded at-rest key."
  }
}

# ---- Alarms (alarms.tf) ----
# Every alarm notifies the <project>-<environment>-alarms SNS topic. The
# defaults suit the reference sizing (1 vCPU / 2 GB task, db.t4g.micro);
# README.md, "Alarms", explains each choice.

variable "alarm_email" {
  description = "Email address subscribed to the alarm topic. AWS sends a confirmation email to it, and no alarm is delivered until the recipient confirms. Empty creates the topic without a subscription (subscribe a pager or chat integration to it instead)."
  type        = string
  default     = ""

  validation {
    condition     = var.alarm_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alarm_email))
    error_message = "alarm_email must be empty or a single email address."
  }
}

variable "alarm_alb_5xx_count" {
  description = "Load-balancer-generated 5xx responses (502/503/504) per 5 minutes that, sustained for two windows in a row, raise the ALB 5xx alarm."
  type        = number
  default     = 20
}

variable "alarm_target_5xx_percent" {
  description = "Share of requests (%) the app answers with a 5xx, sustained for two 5-minute windows, that raises the target 5xx rate alarm. Windows with fewer than 20 requests never alarm."
  type        = number
  default     = 5
}

variable "alarm_target_response_p95_seconds" {
  description = "p95 target response time (seconds), sustained for 15 minutes, that raises the slow-response alarm. Healthy dashboard pages answer well under a second; the state-volume throttling incident pushed signed-in pages to several seconds. Streaming (SSE) responses count only until their headers, so long-running chats do not inflate it."
  type        = number
  default     = 2
}

variable "alarm_ecs_cpu_percent" {
  description = "App task CPU utilisation (%), sustained for 15 minutes, that raises the ECS CPU alarm."
  type        = number
  default     = 80
}

variable "alarm_ecs_memory_percent" {
  description = "App task memory utilisation (%), sustained for 15 minutes, that raises the ECS memory alarm. The container is killed at 100%."
  type        = number
  default     = 80
}

variable "alarm_efs_burst_credit_low_gib" {
  description = "EFS burst credit balance (GiB) below which the burst-credit alarm fires (bursting throughput mode only). A small file system holds at most about 2.1 TiB of credits and sits there while it stays under its baseline, so falling below half means it has been draining for a sustained period."
  type        = number
  default     = 1024
}

variable "alarm_efs_io_limit_percent" {
  description = "EFS PercentIOLimit (General Purpose performance mode I/O limit, %), sustained for 15 minutes, that raises the EFS I/O limit alarm."
  type        = number
  default     = 90
}

variable "alarm_efs_throughput_percent" {
  description = "Metered EFS throughput as a share of PermittedThroughput (%), sustained for 15 minutes, that raises the throughput-utilisation alarm. Works in every throughput mode."
  type        = number
  default     = 80
}

variable "alarm_rds_cpu_percent" {
  description = "Database CPU utilisation (%), sustained for 15 minutes, that raises the RDS CPU alarm."
  type        = number
  default     = 80
}

variable "alarm_rds_free_storage_low_gib" {
  description = "Free database storage (GiB) below which the RDS storage alarm fires. 2 GiB is 10% of the default 20 GB allocation, where RDS storage autoscaling also acts."
  type        = number
  default     = 2
}

variable "alarm_rds_freeable_memory_low_mib" {
  description = "Freeable database memory (MiB), sustained for 15 minutes, below which the RDS memory alarm fires. 100 MiB is about a tenth of a db.t4g.micro; raise it with a larger instance class."
  type        = number
  default     = 100
}

variable "alarm_rds_cpu_credit_low" {
  description = "CPU credit balance below which the RDS CPU-credit alarm fires. Created only for burstable (db.t*) classes; a db.t4g.micro holds at most 288 credits."
  type        = number
  default     = 30
}

variable "alarm_rds_connections_high" {
  description = "Open database connections above which the RDS connections alarm fires. Postgres max_connections scales with instance memory and is under 100 on a db.t4g.micro; raise this with a larger instance class."
  type        = number
  default     = 60
}

# ---- Optional WAF (waf.tf) ----

variable "enable_waf" {
  description = "Create an AWS WAF web ACL (AWS managed Common, Known bad inputs and IP reputation rule groups plus a per-client rate limit) and associate it with the load balancer. Off by default because AWS WAF is billed per web ACL, per rule and per million requests; see AWS WAF pricing."
  type        = bool
  default     = false
}

variable "waf_rate_limit" {
  description = "Requests per client IP in any 5-minute window above which the WAF blocks that client until its rate falls back under the limit. Behind Cloudflare (restrict_ingress_to_cloudflare) the client IP is read from the CF-Connecting-IP header."
  type        = number
  default     = 2000

  validation {
    condition     = var.waf_rate_limit >= 10 && var.waf_rate_limit <= 2000000000
    error_message = "waf_rate_limit must be between 10 and 2,000,000,000 (the AWS WAF range)."
  }
}

variable "waf_common_rule_count_overrides" {
  description = "Extra rules in the AWS managed Common rule set to count instead of block, e.g. [\"CrossSiteScripting_BODY\"] if chat posts that contain code are blocked. SizeRestrictions_BODY is always counted (waf.tf)."
  type        = list(string)
  default     = []
}
