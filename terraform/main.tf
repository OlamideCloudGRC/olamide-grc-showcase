
# Getting the ami using data source
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-kernel-5.10-hvm-2.0.*"]

  }

}



# Creating an intance
resource "aws_instance" "web" {
  for_each = toset(var.availability_zones)
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private_subnet[each.key].id
  vpc_security_group_ids = [aws_security_group.web-sg.id]

  tags = {
    Name = "GRC_HW_2_${each.key}"
  }
}