#--------Creating the VPC-----#
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames

  tags = {
    Name = var.vpc_name
  }
}

#---------Creating a private subnet for webapps----#
resource "aws_subnet" "private_subnet" {
  # Looping through each availability zone
  for_each = toset(var.availability_zones)

  vpc_id = aws_vpc.main.id

  # Using cidrsubnet() to split the VPC range into /24 subnets per AZ to avoid overlap
  cidr_block = cidrsubnet(var.vpc_cidr, 8, index(var.availability_zones, each.key))

  availability_zone = each.key

  # Tagging subnet for identification and organization
  tags = {
    Name = "GRC_HW_2_priv_subnet_${each.key}"
  }
}


#---------Creating a public subnet ----#
resource "aws_subnet" "public_subnet" {
  # Looping through each availability zone
  for_each = toset(var.availability_zones)

  vpc_id = aws_vpc.main.id

  # Offsetting netnum by 10 to avoid CIDR overlap with private subnet
  cidr_block = cidrsubnet(var.vpc_cidr, 8, index(var.availability_zones, each.key) + 10)

  availability_zone = each.key

  map_public_ip_on_launch = true

  # Tagging subnet for identification and organization
  tags = {
    Name = "GRC_HW_2_pub_subnet_${each.key}"
    Tier = "public"
    AZ   = each.key

  }
}


#----------Creating the Internet gateway---------#
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "GRC_HW_2_igw"
  }
}


#-------Creating an Elastic IP for the NAT gateway------#
resource "aws_eip" "eip-nat" {

  #------Looping through the AZs to create one EIP for each AZ for high availability----# 
  for_each = toset(var.availability_zones)

  domain = "vpc"

  tags = {
    Name = "eip_${each.key}"
  }
}

#-------Creating a NAT Gateway for the private subnet ------#
resource "aws_nat_gateway" "NAT_priv_subnet" {
  for_each          = toset(var.availability_zones)
  allocation_id     = aws_eip.eip-nat[each.key].id
  subnet_id         = aws_subnet.public_subnet[each.key].id
  connectivity_type = "public"

  tags = {
    Name = "NAT_${each.key}"
  }
}


#--------Creating route table for private subnet (one per AZ)-----#
resource "aws_route_table" "priv_rt" {
  for_each = toset(var.availability_zones)
  vpc_id   = aws_vpc.main.id

  tags = {
    Name = "priv_rte_${each.key}"
  }
}


#--------Directing traffic from priv subnet to NAT Gateway-------#
resource "aws_route" "priv_internet_access" {
  for_each               = toset(var.availability_zones)
  route_table_id         = aws_route_table.priv_rt[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.NAT_priv_subnet[each.key].id

}

#---------Associating priv route table to the private subnet-------#
resource "aws_route_table_association" "priv-subnet-asso" {
  for_each       = toset(var.availability_zones)
  route_table_id = aws_route_table.priv_rt[each.key].id
  subnet_id      = aws_subnet.private_subnet[each.key].id

}


#--------Creating route table for public subnet (one per AZ)-----#
resource "aws_route_table" "pub_rt" {
  for_each = toset(var.availability_zones)
  vpc_id   = aws_vpc.main.id

  tags = {
    Name = "pub_rte_${each.key}"
  }
}


#---------Route traffic from the public subnet to the internet Gateway---------#
resource "aws_route" "public-internet-access" {
  for_each               = toset(var.availability_zones)
  route_table_id         = aws_route_table.pub_rt[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}



#---------Associating public route table to the public subnet-------#
resource "aws_route_table_association" "pub-subnet-asso" {
  for_each       = toset(var.availability_zones)
  route_table_id = aws_route_table.pub_rt[each.key].id
  subnet_id      = aws_subnet.public_subnet[each.key].id

}
