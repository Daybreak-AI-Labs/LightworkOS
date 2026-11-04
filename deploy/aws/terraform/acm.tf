# TLS for the custom domain. DNS lives in Cloudflare (not Route 53), so
# validation is a two-step apply: create the cert, publish the emitted
# validation CNAME(s) in Cloudflare, then let aws_acm_certificate_validation
# confirm. The cert is regional (us-east-2, same as the ALB) — an ALB reads a
# cert from its own region, unlike CloudFront which requires us-east-1.
resource "aws_acm_certificate" "app" {
  count             = var.domain_name != "" ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${local.name}-cert" }
}

# Waits until the DNS validation record (created in Cloudflare, out of band)
# resolves and ACM issues the cert. The validation record name/value are
# exposed via the acm_validation_records output for that manual step.
resource "aws_acm_certificate_validation" "app" {
  count           = var.domain_name != "" ? 1 : 0
  certificate_arn = aws_acm_certificate.app[0].arn

  validation_record_fqdns = [
    for dvo in aws_acm_certificate.app[0].domain_validation_options : dvo.resource_record_name
  ]

  timeouts {
    create = "30m"
  }
}
