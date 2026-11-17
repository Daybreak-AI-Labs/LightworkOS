"""The AWS deploy stack's posture (deploy/aws/terraform), pinned as text.

Terraform is not installed in CI, so these read the HCL as text: every secret
keeps a recovery window, the state volume is backed up, the identifiers of
people are not tracked, the deployer identity is region-bound and can never
delete the data stores, the service can be pinned to an image digest, the
launch metrics are alarmed, and the optional WAF stays off until enabled.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TERRAFORM = REPO_ROOT / "deploy" / "aws" / "terraform"


def _tf(name: str) -> str:
    return (TERRAFORM / name).read_text(encoding="utf-8")


def _blocks(text: str, kind: str) -> dict[str, str]:
    """Top-level ``resource "<kind>" "<name>" { ... }`` bodies by name."""
    pattern = rf'^resource "{re.escape(kind)}" "([a-z0-9_]+)" \{{(.*?)\n\}}'
    return dict(re.findall(pattern, text, re.DOTALL | re.MULTILINE))


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



def test_the_launch_metrics_are_alarmed():
    alarms_tf = _tf("alarms.tf")
    alarms = _blocks(alarms_tf, "aws_cloudwatch_metric_alarm")
    for metric in (
        "HTTPCode_ELB_5XX_Count", "HTTPCode_Target_5XX_Count", "RequestCount",
        "UnHealthyHostCount", "TargetResponseTime", "RunningTaskCount",
        "DesiredTaskCount", "MemoryUtilization", "BurstCreditBalance",
        "PercentIOLimit", "MeteredIOBytes", "PermittedThroughput",
        "FreeStorageSpace", "FreeableMemory", "CPUCreditBalance",
        "DatabaseConnections",
    ):
        assert any(f'metric_name = "{metric}"' in body
                   or f'metric_name         = "{metric}"' in body
                   for body in alarms.values()), metric
    cpu = [body for body in alarms.values() if '"CPUUtilization"' in body]
    assert {'"AWS/ECS"' in b for b in cpu} == {True, False}  # ECS and RDS
    for name, body in alarms.items():
        assert "alarm_description" in body, name
        assert re.search(r"alarm_actions\s*=\s*local\.alarm_actions", body), name
        assert re.search(r"treat_missing_data\s*=", body), name
    assert 'extended_statistic  = "p95"' in alarms["target_response_time_p95"]
    assert 'treat_missing_data  = "breaching"' in alarms["ecs_running_tasks"]
    assert 'expression  = "desired - running"' in alarms["ecs_running_tasks"]
    # Burst credits only matter in bursting mode; the utilisation alarm works in every mode.
    assert "count               = local.efs_bursting ? 1 : 0" in alarms["efs_burst_credits_low"]
    assert "count" not in alarms["efs_throughput_utilisation"].split("metric_query")[0]
    assert 'startswith(var.db_instance_class, "db.t")' in alarms["rds_cpu_credits_low"]
    assert 'resource "aws_sns_topic" "alarms"' in alarms_tf
    subscription = _blocks(alarms_tf, "aws_sns_topic_subscription")["alarm_email"]
    assert 'count     = var.alarm_email != "" ? 1 : 0' in subscription
    variables = _tf("variables.tf")
    email = re.search(r'variable "alarm_email" \{(.*?)\n\}', variables, re.DOTALL).group(1)
    assert 'default     = ""' in email
    assert 'value = "enabled"' in _tf("ecs.tf")  # Container Insights feeds the task counts
    deployer = _tf("deployer.tf")
    assert 'sid     = "Alarms"' in deployer and 'sid     = "AlarmTopic"' in deployer
    assert "## Alarms" in _tf("README.md")


def test_the_waf_is_off_by_default_and_rate_limits_when_on():
    variables = _tf("variables.tf")
    enable = re.search(r'variable "enable_waf" \{(.*?)\n\}', variables, re.DOTALL).group(1)
    assert "default     = false" in enable
    rate = re.search(r'variable "waf_rate_limit" \{(.*?)\n\}', variables, re.DOTALL).group(1)
    assert "default     = 2000" in rate
    waf = _tf("waf.tf")
    acl = _blocks(waf, "aws_wafv2_web_acl")["main"]
    assert "count       = var.enable_waf ? 1 : 0" in acl
    assert 'scope       = "REGIONAL"' in acl
    assert "rate_based_statement" in acl
    assert "limit              = var.waf_rate_limit" in acl
    for group in ("AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
                  "AWSManagedRulesAmazonIpReputationList"):
        assert f'name        = "{group}"' in acl, group
    # Large chat posts and uploads must not be blocked by the 8 KB body rule.
    assert 'concat(["SizeRestrictions_BODY"]' in waf
    assert "rule_action_override" in acl and "count {}" in acl
    association = _blocks(waf, "aws_wafv2_web_acl_association")["alb"]
    assert "count        = var.enable_waf ? 1 : 0" in association
    assert "resource_arn = aws_lb.main.arn" in association
    assert "web_acl_arn  = aws_wafv2_web_acl.main[0].arn" in association
    infra = re.search(r'sid = "Infra"(.*?)\n  \}', _tf("deployer.tf"), re.DOTALL).group(1)
    assert '"wafv2:*"' in infra  # region-bound with the rest of the infrastructure
    readme = _tf("README.md")
    assert "## Optional WAF" in readme and "AWS WAF pricing" in readme
    assert "## Check for drift before launch" in readme
