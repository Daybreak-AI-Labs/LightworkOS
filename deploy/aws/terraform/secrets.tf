# Generated credentials. Alphanumeric-only so they embed in a DSN URL and an
# HTTP header without escaping.
resource "random_password" "db" {
  length  = 28
  special = false
}

resource "random_password" "dashboard_token" {
  length  = 48
  special = false
}

# ---- Secrets Manager entries (injected into the task, never baked into the image) ----
#
# Every entry keeps the 7-day recovery window (the shortest AWS allows above
# immediate deletion), so a secret destroyed by a wrong apply can be restored
# with `aws secretsmanager restore-secret`. An intentional teardown that must
# reuse a name at once deletes with
# `aws secretsmanager delete-secret --force-delete-without-recovery` first.

resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${local.name}/db-password"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db.result
}

resource "aws_secretsmanager_secret" "dashboard_token" {
  name                    = "${local.name}/dashboard-token"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "dashboard_token" {
  secret_id     = aws_secretsmanager_secret.dashboard_token.id
  secret_string = random_password.dashboard_token.result
}

# The provider API key: created as a placeholder so the task definition can
# reference a stable ARN. The real value is written out-of-band (Terraform must
# not hold it in state), e.g.:
#   aws secretsmanager put-secret-value --secret-id lightwork-prod/anthropic-api-key \
#     --secret-string 'sk-ant-...' --profile lightwork --region us-east-2
resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name                    = "${local.name}/anthropic-api-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "anthropic_api_key" {
  secret_id     = aws_secretsmanager_secret.anthropic_api_key.id
  secret_string = "REPLACE_ME" # pragma: allowlist secret -- placeholder, not a real key

  # The real key is rotated in out-of-band; do not let Terraform revert it.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ---- OIDC browser login (Auth0) ----
# Signs the dashboard's own session cookie after a successful OIDC login.
# Terraform generates and owns this one.
resource "random_password" "oidc_session_secret" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "oidc_session_secret" {
  name                    = "${local.name}/oidc-session-secret"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "oidc_session_secret" {
  secret_id     = aws_secretsmanager_secret.oidc_session_secret.id
  secret_string = random_password.oidc_session_secret.result
}

# The Auth0 application client secret. Placeholder here so the task can
# reference a stable ARN; the real value is written out-of-band (never in
# Terraform state), e.g.:
#   aws secretsmanager put-secret-value --secret-id lightwork-prod/oidc-client-secret \
#     --secret-string '<auth0-client-secret>' --profile lightwork --region us-east-2
resource "aws_secretsmanager_secret" "oidc_client_secret" {
  name                    = "${local.name}/oidc-client-secret"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "oidc_client_secret" {
  secret_id     = aws_secretsmanager_secret.oidc_client_secret.id
  secret_string = "REPLACE_ME" # pragma: allowlist secret -- placeholder, not a real secret

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# The platform mailer sends via the Amazon SES API using the ECS task role
# (see the "SESSend" statement in iam.tf) — no SMTP username/password to store.

# Full Postgres DSN, assembled from the RDS endpoint. Alphanumeric password
# means no URL-encoding is required.
# sslmode=require encrypts the connection to RDS without a CA bundle in the
# image. deploy/postgres/README.md asks for verify-full, which needs the RDS CA
# bundle shipped and pinned in the image; this stack does not ship it.
resource "aws_secretsmanager_secret" "pg_dsn" {
  name                    = "${local.name}/pg-dsn"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "pg_dsn" {
  secret_id     = aws_secretsmanager_secret.pg_dsn.id
  secret_string = "postgresql://${var.db_username}:${random_password.db.result}@${aws_db_instance.main.address}:5432/${var.db_name}?sslmode=require" # pragma: allowlist secret -- Terraform interpolation, no literal secret
}

# At-rest encryption key. The kernel otherwise generates one on first use under
# the task's data dir, which is ephemeral on Fargate: every task replacement
# minted a new key and every goal sealed under the previous key became
# unreadable (cryptography InvalidTag on /goals and /chat). Pin it here so the
# key survives deploys. 32 bytes, hex-encoded, as crypto_at_rest expects.
resource "random_id" "at_rest_key" {
  byte_length = 32
}

resource "aws_secretsmanager_secret" "at_rest_key" {
  name                    = "${local.name}/at-rest-encryption-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "at_rest_key" {
  secret_id     = aws_secretsmanager_secret.at_rest_key.id
  secret_string = random_id.at_rest_key.hex
}

# Native consent SDK receipt signing root. The dashboard's
# [consent_preferences.native_sdk] contract names an environment variable
# (receipt_key_secret_ref) and derives a per-tenant Ed25519 receipt key from
# its value; without it the module reports its configuration as incomplete
# and refuses to start. 32 bytes of entropy, "hex:"-prefixed as
# consent_native_composition._secret_material expects. Rotating it
# invalidates every receipt signed so far, hence the recovery window.
resource "random_id" "consent_receipt_root" {
  byte_length = 32
}

resource "aws_secretsmanager_secret" "consent_receipt_root" {
  name                    = "${local.name}/consent-receipt-root"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "consent_receipt_root" {
  secret_id     = aws_secretsmanager_secret.consent_receipt_root.id
  secret_string = "hex:${random_id.consent_receipt_root.hex}" # pragma: allowlist secret -- Terraform interpolation, no literal secret
}
