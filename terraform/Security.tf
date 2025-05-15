

# Creating the security group for the web instance
resource "aws_security_group" "web-sg" {
  vpc_id      = aws_vpc.main.id
  name        = "priv_sub_web_sg"
  description = "security group for the web server"
}


# Creating the security rule for the web instance
resource "aws_security_group_rule" "ssh" {
  security_group_id = aws_security_group.web-sg.id
  description       = "Allow SSH traffic"
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = [aws_vpc.main.cidr_block]
}