locals {
  standard_tags = merge(
    {
      Terraform    = "true"
      LastModified = formatdate("YYYY-MM-DD", timestamp())
      Environment  = var.environment
    },
    var.compliance_tags
  )
}

locals {

  # Ensure we dont request more AZs than available
  az_count = min(var.max_azs, length(data.aws_availability_zones.current_region.zone_ids))

  # Take first N zone_ids (list) to presrve AWS order
  az_ids = slice(data.aws_availability_zones.current_region.zone_ids, 0, local.az_count)

  # Build a stable map: zone_id => az_name 
  availability_zones = {
    for i, zid in local.az_ids :
    zid => data.aws_availability_zones.current_region.names[i]
  }

  public_subnets = {
    for i, zid in local.az_ids :
    zid => {
      name = local.availability_zones[zid]
      cidr = cidrsubnet(var.vpc_cidr, var.subnet_bits, i * var.subnet_stride + 0)
    }
  }

  private_subnets = {
    for i, zid in local.az_ids :
    zid => {
      name = local.availability_zones[zid]
      cidr = cidrsubnet(var.vpc_cidr, var.subnet_bits, i * var.subnet_stride + 1)
    }
  }
}




