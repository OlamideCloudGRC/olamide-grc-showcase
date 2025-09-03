
# Create ALB
resource "aws_lb" "app_lb" {
  name               = "app-lb-${var.environment}-${var.region}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = values(aws_subnet.public_subnet)[*].id

  enable_deletion_protection = var.environment == "Prod" ? true : false
  idle_timeout               = var.alb_idle_timeout
  enable_http2               = true
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.alb_log_bucket.id
    enabled = true
  }

  tags = merge(
    local.standard_tags,
    {
      Name        = "alb-${var.environment}"
      Description = "Application Load Balancer for ${var.environment} environment"
    }
  )

}

# Create ALB Target group
resource "aws_lb_target_group" "alb_tg" {
  name        = "alb-tg-${var.environment}-${var.region}"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id

  deregistration_delay = 30
  slow_start           = var.environment == "Prod" ? 60 : 30

  health_check {
    enabled             = true
    path                = var.health_check_path
    port                = "traffic-port"
    interval            = 10
    matcher             = "200-399"
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2

  }

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    local.standard_tags,
    {
      Name = "alb-tg-${var.environment}"
    }
  )

}


# Create HTTP Listner (will redirect to HTTPS)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Create HTTPS listner
resource "aws_lb_listener" "https" {
  depends_on = [ aws_acm_certificate_validation.alb_cert ]
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.alb_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_tg.arn
  }

}


# Route 53: Create A record that maps domaine name to elb
resource "aws_route53_record" "root_to_alb" {
  zone_id = data.aws_route53_zone.main_zone.id
  name = data.aws_route53_zone.main_zone.name
  type = "A"

  alias {
    name = aws_lb.app_lb.dns_name
    zone_id = aws_lb.app_lb.zone_id
    evaluate_target_health = false 
  }
}

# Route 53: Create A record that maps domaine name to elb
resource "aws_route53_record" "www_to_alb" {
  zone_id = data.aws_route53_zone.main_zone.id
  name = "www"
  type = "A"

  alias {
    name = aws_lb.app_lb.dns_name
    zone_id = aws_lb.app_lb.zone_id
    evaluate_target_health = false 
  }
}