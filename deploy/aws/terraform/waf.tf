# Optional AWS WAF in front of the load balancer. Off by default because it is
# billed per web ACL, per rule and per million requests (see AWS WAF pricing);
# set enable_waf = true to create it (README.md, "Optional WAF").
#
# ALB health checks are sent by the load balancer to the task's private IP, not
# through a listener, so this web ACL never sees them and the rate rule cannot
# fail the target. External uptime probes of /livez, /readyz or /healthz do
# pass through it and are rate-limited like any other client; one probe a
# minute is far below the limit. The health paths are not exempted, because
# /readyz and /healthz run dependency checks that an unthrottled flood could
# turn against the database.

locals {
  # Behind Cloudflare the ALB only sees Cloudflare's edge addresses (network.tf),
  # so a per-source-IP limit would throttle whole edge locations. Rate-limit on
  # the client address Cloudflare forwards instead; only Cloudflare can reach
  # the ALB in that mode, and it sets this header itself.
  waf_client_ip_header = "CF-Connecting-IP"

  # SizeRestrictions_BODY blocks any body over 8 KB, the most an ALB lets WAF
  # inspect. Chat posts, document uploads, SAML responses and JSON imports are
  # routinely larger, so it only counts; the app enforces its own per-route
  # body limits. The other body rules inspect only the first 8 KB.
  waf_common_count_rules = distinct(concat(["SizeRestrictions_BODY"], var.waf_common_rule_count_overrides))
}

resource "aws_wafv2_web_acl" "main" {
  count       = var.enable_waf ? 1 : 0
  name        = "${local.name}-alb"
  description = "Managed rule groups and a per-client rate limit in front of the ${local.name} load balancer."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit-per-client-ip"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        # Requests per client IP in any 5-minute window.
        limit              = var.waf_rate_limit
        aggregate_key_type = var.restrict_ingress_to_cloudflare ? "FORWARDED_IP" : "IP"

        dynamic "forwarded_ip_config" {
          for_each = var.restrict_ingress_to_cloudflare ? [1] : []
          content {
            header_name = local.waf_client_ip_header
            # A request without the header did not come through Cloudflare.
            fallback_behavior = "MATCH"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        dynamic "rule_action_override" {
          for_each = local.waf_common_count_rules
          content {
            name = rule_action_override.value
            action_to_use {
              count {}
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-alb"
    sampled_requests_enabled   = true
  }

  tags = { Name = "${local.name}-alb" }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count        = var.enable_waf ? 1 : 0
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main[0].arn
}
