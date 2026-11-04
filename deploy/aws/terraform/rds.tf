resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db"
  subnet_ids = aws_subnet.private[*].id
  tags       = { Name = "${local.name}-db" }
}

# Keep the final snapshot name stable across ordinary plans. Rotate this ID
# before a separately reviewed second database retirement to avoid a name
# collision with the first final snapshot.
resource "random_id" "db_final_snapshot" {
  byte_length = 8
}

resource "aws_db_instance" "main" {
  identifier     = "${local.name}-pg"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username
  password = random_password.db.result
  port     = 5432

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  multi_az               = false

  backup_retention_period   = 7
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name}-pg-final-${random_id.db_final_snapshot.hex}"
  apply_immediately         = true

  tags = { Name = "${local.name}-pg" }

  # A surprising replacement must stop at the plan, not delete the live DB.
  # Intentional retirement requires a separately reviewed config change and
  # disabling AWS deletion protection before the final snapshot can be taken.
  lifecycle {
    prevent_destroy = true
  }
}
