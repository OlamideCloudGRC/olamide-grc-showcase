
###------------------------------------------------------
# ALB sceurity group and components
# Security groups + ingress rules + egress rules
###------------------------------------------------------

# Create security group for ALB
resource "aws_security_group" "alb_sg" {
  name        = "alb-sg-${var.environment}"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  egress {
    description = "Allow all outgoing traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }

  tags = merge(
    local.standard_tags,
    {
      Name = "alb-sg-${var.environment}"
    }
  )
}

