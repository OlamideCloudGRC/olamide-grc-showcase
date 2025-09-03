
# Assume role policy for EC2 role
data "aws_iam_policy_document" "app_instance_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Create a role for EC2
resource "aws_iam_role" "app_instance_role" {
  name               = "grc-app-instance-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.app_instance_role.json
  path               = "/portfolio/"
  tags = {
    Project = "GRC-Portfolio"
  }
}

# Attach policy
resource "aws_iam_role_policy_attachment" "app_ssm_attachment" {
  role       = aws_iam_role.app_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}


# Create EC2 Instance profile
resource "aws_iam_instance_profile" "app_instance_profile" {
  name = "grc-app-instance-profile-${var.environment}"
  role = aws_iam_role.app_instance_role.name
}




# Launch template
resource "aws_launch_template" "web_lt" {
  name_prefix            = "web_lt-${var.environment}"
  image_id               = data.aws_ami.latest_grc_ami.id
  instance_type          = var.instance_type
  ebs_optimized          = true
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  
  iam_instance_profile {
    name = aws_iam_instance_profile.app_instance_profile.name
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      encrypted             = false
      delete_on_termination = true
      
    }
  }
  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Update system and install web server
    yum update -y
    yum install -y httpd

    # Start and enable httpd service
    systemctl start httpd
    systemctl enable httpd

    # Create health check page
    echo "Healthy" > /var/www/html/health

    # Create a simple homepage
    echo "<html><body><h1>Hi, I am Olamide Solola and I am a security Engineer</h1></body></html>" > /var/www/html/index.html

  EOF
  )

  # Metadata
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name         = "GRC-Security_App-${var.environment}"
      Environment  = var.environment
      Project      = "GRC-Portfolio"
      SecurityTier = "protected"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name         = "GRC-Security-App-Volume"
      Environment  = var.environment
      Project      = "GRC-Portfolio"
      SecurityTier = "protected"
    }
  }

  tags = {
    Name        = "GRC-Security-Launch-Template"
    Environment = var.environment
  }

  lifecycle {
    create_before_destroy = true
  }

}

# Create autoscaling group
resource "aws_autoscaling_group" "grc_asg" {
  name_prefix               = "grc-security-asg-${var.environment}"
  max_size                  = var.max_size
  min_size                  = var.min_size
  health_check_grace_period = 600
  health_check_type         = "ELB"
  vpc_zone_identifier       = values(aws_subnet.private_subnets)[*].id
  desired_capacity          = var.min_size
  launch_template {
    id      = aws_launch_template.web_lt.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.alb_tg.arn]

  lifecycle {
    create_before_destroy = true
  }


  # Tags for all instances
  tag {
    key                 = "Name"
    value               = "GRC-Security-App-${var.environment}"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }

  tag {
    key                 = "Project"
    value               = "GRC-Portfolio"
    propagate_at_launch = true
  }

  tag {
    key                 = "SecurityTier"
    value               = "Protected"
    propagate_at_launch = true
  }

  tag {
    key                 = "Compliance"
    value               = "PCI-DSS, HIPAA"
    propagate_at_launch = true
  }


}


# Autoscaling Policies
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "grc-app-scale-out"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.grc_asg.name
}

resource "aws_autoscaling_policy" "scale_in" {
  name                   = "grc-app-scale-in"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.grc_asg.name
}



# Cloudwatch alarm for CPU utilization
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "grc-app-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 70
  alarm_description   = "Scale out when CPU utilization exceeds 70% for 2 periods"
  treat_missing_data  = "notBreaching"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.grc_asg.name
  }

  alarm_actions = [aws_autoscaling_policy.scale_out.arn]

  tags = {
    Name        = "GRC-High-CPU-Alarm"
    Environment = var.environment
  }

}


# Cloudwatch alarm for CPU utilization
resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "grc-app-low-cpu"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 30
  alarm_description   = "Scale in when CPU utilization is below exceeds 30% for 3 periods"
  treat_missing_data  = "notBreaching"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.grc_asg.name
  }

  alarm_actions = [aws_autoscaling_policy.scale_in.arn]

  tags = {
    Name        = "GRC-Low-CPU-Alarm"
    Environment = var.environment
  }

}