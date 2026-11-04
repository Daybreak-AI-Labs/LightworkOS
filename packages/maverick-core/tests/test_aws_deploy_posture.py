"""The AWS deploy stack's posture (deploy/aws/terraform), pinned as text.

Terraform is not installed in CI, so these read the HCL as text: every secret
keeps a recovery window, the state volume is backed up, the identifiers of
people are not tracked, the deployer identity is region-bound and can never
delete the data stores, and the service can be pinned to an image digest.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TERRAFORM = REPO_ROOT / "deploy" / "aws" / "terraform"


def _tf(name: str) -> str:
    return (TERRAFORM / name).read_text(encoding="utf-8")


def test_every_secret_keeps_a_recovery_window():
    secrets = _tf("secrets.tf")
    windows = re.findall(r"recovery_window_in_days\s*=\s*(\d+)", secrets)
    assert len(windows) == secrets.count('resource "aws_secretsmanager_secret" ')
    assert windows and all(int(days) >= 7 for days in windows), windows


def test_the_state_volume_is_backed_up():
    efs = _tf("efs.tf")
    policy = re.search(
        r'resource "aws_efs_backup_policy" "state" \{(.*?)\n\}', efs, re.DOTALL,
    )
    assert policy is not None
    assert "file_system_id = aws_efs_file_system.state.id" in policy.group(1)
    assert 'status = "ENABLED"' in policy.group(1)
    assert "prevent_destroy = true" in efs


def test_identifiers_of_people_are_not_tracked():
    tracked = subprocess.run(
        ["git", "ls-files", "--", "deploy/aws/terraform/oidc.auto.tfvars",
         "deploy/aws/terraform/local.auto.tfvars"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    assert tracked.stdout == ""
    example = _tf("local.auto.tfvars.example")
    assert re.search(r"^dashboard_admins\s*=", example, re.MULTILINE)
    assert re.search(r"^email_from\s*=", example, re.MULTILINE)
    assert "<sub>" in example and "<name>" in example  # placeholders, not people
    ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "deploy/aws/terraform/local.auto.tfvars" in ignored
    runbook = _tf("README.md")
    assert "cp deploy/aws/terraform/local.auto.tfvars.example deploy/aws/terraform/local.auto.tfvars" in runbook


def test_the_deployer_is_region_bound_and_cannot_delete_the_data_stores():
    deployer = _tf("deployer.tf")
    infra = re.search(r'sid = "Infra"(.*?)\n  \}', deployer, re.DOTALL).group(1)
    assert 'variable = "aws:RequestedRegion"' in infra
    assert "values   = [data.aws_region.current.name]" in infra
    deny = re.search(r'sid    = "NeverDeleteDataStores"(.*?)\n  \}', deployer, re.DOTALL).group(1)
    assert 'effect = "Deny"' in deny
    for action in (
        "rds:DeleteDBInstance", "rds:DeleteDBCluster", "rds:DeleteDBSnapshot",
        "rds:DeleteDBClusterSnapshot", "elasticfilesystem:DeleteFileSystem",
    ):
        assert f'"{action}"' in deny, action
    # Terraform must still be able to manage the stack it protects.
    assert "rds:ModifyDBInstance" not in deny
    assert "elasticfilesystem:PutBackupPolicy" not in deny
    assert "condition" not in deny
    assert 'sid       = "NeverAssumeRole"' in deployer


def test_the_service_can_be_pinned_to_an_image_digest():
    variables = _tf("variables.tf")
    digest = re.search(r'variable "image_digest" \{(.*?)\n\}', variables, re.DOTALL).group(1)
    assert 'default     = ""' in digest
    assert 'can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))' in digest
    ecs = _tf("ecs.tf")
    assert 'var.image_digest != ""' in ecs
    assert '"${aws_ecr_repository.app.repository_url}@${var.image_digest}"' in ecs
    assert '"${aws_ecr_repository.app.repository_url}:${var.image_tag}"' in ecs
    assert "### 4b. Pin the image you just built" in _tf("README.md")

