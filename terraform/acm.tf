
# Request ACM in the same region as ALB
resource "aws_acm_certificate" "alb_cert" {
  domain_name       = data.aws_route53_zone.main_zone.name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    local.standard_tags,
    {
      Name = "alb-acm-${var.region}-${var.environment}"

    }
  )
}

# Reference domain Validation
resource "aws_route53_record" "alb_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.alb_cert.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  name    = each.value.name
  records = [each.value.record]
  ttl     = 60
  type    = each.value.type
  zone_id = data.aws_route53_zone.main_zone.id

}

# ACM Validation using DNS records
resource "aws_acm_certificate_validation" "alb_cert" {
  certificate_arn         = aws_acm_certificate.alb_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.alb_cert_validation : record.fqdn]
}