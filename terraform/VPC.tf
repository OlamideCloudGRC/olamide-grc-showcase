###------------------------------------------------------
# VPC 
###------------------------------------------------------


# Create VPC
resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  # Enable DNS Support for DNS resolution
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Main-VPC"
  }
}

###------------------------------------------------------
# Public subnets and components
# Public Subnets + Internet gateway + route table
###------------------------------------------------------

# Create public subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main.id
  for_each                = local.public_subnets
  cidr_block              = each.value.cidr
  availability_zone       = each.value.name
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-${each.value.name}"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "main-igw"
  }
}

# Create one public route table for public subnets
resource "aws_route_table" "public_rtb" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}

# Create route table association
resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public_subnet
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public_rtb.id
}

###------------------------------------------------------
# Private subnets and components
# Private Subnets + NAT gateway + route table
###------------------------------------------------------

# Create Private Subnets
resource "aws_subnet" "private_subnets" {
  vpc_id            = aws_vpc.main.id
  for_each          = local.private_subnets
  cidr_block        = each.value.cidr
  availability_zone = each.value.name

  tags = {
    Name = "private-subnet-${each.value.name}"
  }

}

# Create EIP for NAT Gateway
resource "aws_eip" "nat_eip" {
  for_each = local.private_subnets
  domain   = "vpc"

  tags = {
    Name = "nat-eip-${each.value.name}"
  }
}

# Create NAT Gateway
resource "aws_nat_gateway" "nat" {
  for_each      = local.private_subnets
  allocation_id = aws_eip.nat_eip[each.key].id
  subnet_id     = aws_subnet.public_subnet[each.key].id

  tags = {
    Name = "nat-${each.value.name}"
  }

  depends_on = [aws_internet_gateway.igw]
}

# Create private route table
resource "aws_route_table" "private_rtb" {
  for_each = local.private_subnets
  vpc_id   = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[each.key].id
  }

  tags = {
    Name = "private-route-table-${each.value.name}"
  }
}


# Route table association
resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private_subnets
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private_rtb[each.key].id
}