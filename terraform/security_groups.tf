
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


###------------------------------------------------------
# Instance security group and components
# Security groups + ingress rules + egress rules
###------------------------------------------------------
#--------------- Creating Security Group for Bastion server ----------
resource "aws_security_group" "bastion_sg" {
  name        = "Bastion_SG"
  description = "Security Group for the Bastion Server"
  vpc_id      = aws_vpc.main.id

  # Allow ssh to the bastion server
  ingress {
    description = "Allow inbound SSH traffic to the Bastion server"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "GRC-Bastion-Security-Group"
    Environment = var.environment
  }

}



resource "aws_security_group" "app_sg" {
  name        = "grc-app-sg"
  description = "Security group for GRC application instances"
  vpc_id      = aws_vpc.main.id

  # Allow SSH from bastion only
  ingress {
    description     = "SSH from bastion host"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }

  # Allow HTTP from ALB only
  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Allow outbound traffic
  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "GRC-App-Security-Group"
    Environment = var.environment
  }
}

###------------------------------------------------------
# Quarantine Security group for compromised instance
# Security groups + ingress rules + egress rules
###------------------------------------------------------

resource "aws_security_group" "quarantine_sg" {
  name        = var.quarantine_sg_name
  description = "Quarantine SG: isolate compromised instances (no inbound or outbound)"
  vpc_id      = aws_vpc.main.id

  # Explicitly ensure NO inbound
  ingress = []

  # Explicitly ensure NO Outbound
  egress = [] # ensures AWS default outbound rule is revoked

  tags = {
    Name        = var.quarantine_sg_name
    Purpose     = "EC2-Quarantine"
    ManagedBy   = "Terraform"
    Project     = "GRC-Portfolio"
    Environment = var.environment
  }
}