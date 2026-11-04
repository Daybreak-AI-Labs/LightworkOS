# Persistent state for ~/.maverick.
#
# Fargate task storage is ephemeral. Before this volume existed, every redeploy
# wiped everything the platform keeps on disk: the tenant/workspace registry
# (plans, feature overrides), RBAC role assignments, pending invites,
# department access, and the dashboard's sealed provider keys. Only the Postgres
# world model survived. EFS gives the single-replica control plane durable POSIX
# state; the access point pins the container's uid/gid 1000 (Dockerfile) so the
# non-root process can write regardless of the client identity.
resource "aws_efs_file_system" "state" {
  encrypted = true
  tags      = { Name = "${local.name}-state" }

  # This is the operating state of the deployment. Never let a destroy take it.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_security_group" "efs" {
  name        = "${local.name}-efs"
  description = "EFS state volume: NFS only from the app tasks."
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "NFS from app tasks"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-efs" }
}

# Daily AWS Backup copies of the state volume under the account's default EFS
# backup plan (daily, 35-day retention, default vault). The world model, the
# audit chain and uploaded files live on this volume: prevent_destroy keeps
# the filesystem, this keeps its contents recoverable.
resource "aws_efs_backup_policy" "state" {
  file_system_id = aws_efs_file_system.state.id

  backup_policy {
    status = "ENABLED"
  }
}

# One mount target per AZ the tasks run in (they run in the public subnets).
resource "aws_efs_mount_target" "state" {
  count           = 2
  file_system_id  = aws_efs_file_system.state.id
  subnet_id       = aws_subnet.public[count.index].id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "state" {
  file_system_id = aws_efs_file_system.state.id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/maverick"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "0750"
    }
  }

  tags = { Name = "${local.name}-state" }
}
