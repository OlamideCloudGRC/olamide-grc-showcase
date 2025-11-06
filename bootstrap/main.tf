# Get caller identity
data "aws_caller_identity" "current" {}

# Get current user
data "aws_iam_user" "terraform_user" {
  user_name = var.iam_user_name
}



# Create Terraform execution role
resource "aws_iam_role" "terraform_exec" {
  name        = var.terraform_exec_role_name
  description = "Lest-priviledge role used to deploy the portfolio main stack"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAssume"
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_iam_user.terraform_user.arn
        }
      }
    ]
  })

  tags = {
    Project     = "GRC-Portfolio"
    Environment = "Bootstrap"
    ManagedBy   = "Terraform"
  }
}

# IAM policy attachments
resource "aws_iam_role_policy_attachment" "terraform_exec_core" {
  role       = aws_iam_role.terraform_exec.name
  policy_arn = aws_iam_policy.terraform_exec_core.arn
}

resource "aws_iam_role_policy_attachment" "terraform_exec_iam" {
  role       = aws_iam_role.terraform_exec.name
  policy_arn = aws_iam_policy.terraform_exec_iam.arn
}

resource "aws_iam_role_policy_attachment" "terraform_exec_s3" {
  role       = aws_iam_role.terraform_exec.name
  policy_arn = aws_iam_policy.terraform_exec_s3.arn
}

resource "aws_iam_role_policy_attachment" "terraform_exec_ec2" {
  role       = aws_iam_role.terraform_exec.name
  policy_arn = aws_iam_policy.terraform_exec_ec2.arn
}

resource "aws_iam_role_policy_attachment" "terraform_exec_elb" {
  role       = aws_iam_role.terraform_exec.name
  policy_arn = aws_iam_policy.terraform_exec_elb.arn
}

resource "aws_iam_role_policy_attachment" "terraform_exec_asg" {
  role       = aws_iam_role.terraform_exec.name
  policy_arn = aws_iam_policy.terraform_exec_asg.arn
}

resource "aws_iam_role_policy_attachment" "terraform_exec_services" {
  role       = aws_iam_role.terraform_exec.name
  policy_arn = aws_iam_policy.terraform_exec_services.arn
}

# Terraform exec core permissions 
resource "aws_iam_policy" "terraform_exec_core" {
  name        = "TerraformExecCorePermissions"
  description = "Core permissions for Terraform state management"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Allow state bucket access
      {
        Sid    = "S3StateBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::grc-terraform-state-us-east-1",
          "arn:aws:s3:::grc-terraform-state-us-east-1/*"
        ]

      },

      # Deny dangerous state bucket management 
      {
        Sid    = "S3DenyStateBucketManagement"
        Effect = "Deny"
        Action = [
          "s3:DeleteBucket",
          "s3:PutBucketPolicy",
          "s3:PutEncryptionConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::grc-terraform-state-us-east-1",
          "arn:aws:s3:::grc-terraform-state-us-east-1/*"
        ]
      },

      # Allow DynamoDB State management
      {
        Sid    = "DynamoDBStateLockAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:DescribeTimeToLive",
          "dynamodb:ListTagsOfResource"

        ]
        Resource = [
          "arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/terraform-lock-grc-test"

        ]
      }
    ]
  })
}

# Terraform exec iam permissions
resource "aws_iam_policy" "terraform_exec_iam" {
  name        = "TerraformExecIAMPermissions"
  description = "IAM permissions for Terraform execution role"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Allow IAM get all roles
      {
        Sid    = "IamGetRoleGlobal"
        Effect = "Allow"
        Action = [
          "iam:GetRole"
        ]
        Resource = ["*"]

      },

      # Allow IAM list all roles
      {
        Sid    = "IamListRolesGlobal"
        Effect = "Allow"
        Action = [
          "iam:ListRoles"
        ]
        Resource = ["*"]

      },

      # Allow Terraform's pre-create/pre-destroy discovery on roles that may not exist
      {
        Sid    = "IamPrecreateDiscovery"
        Effect = "Allow"
        Action = [
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetRolePolicy"
        ]
        Resource = ["*"]

      },


      # Allow IAM read for Portfolio roles
      {
        Sid    = "IamReadPortfolioRoles"
        Effect = "Allow"
        Action = [
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole"

        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/*",
        ]

      },

      # Allow create roles only when request includes project = GRC-Portfolio
      {
        Sid      = "IamCreatePortfolioRoles"
        Effect   = "Allow"
        Action   = ["iam:CreateRole"]
        Resource = "*"
        Condition = {
          "StringEquals" : {
            "aws:RequestTag/Project" : "GRC-Portfolio"
          }
        }

      },

      # Tagging roles under /Portfolio/
      {
        Sid      = "IamTagPortfolioRoles"
        Effect   = "Allow"
        Action   = ["iam:TagRole"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/*"
        Condition = {
          "StringEquals" : {
            "aws:RequestTag/Project" : "GRC-Portfolio"
          },

        }
      },

      # UnTagging roles under /Portfolio/
      {
        Sid      = "IamUnTagPortfolioRoles"
        Effect   = "Allow"
        Action   = ["iam:UntagRole"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/*"
        Condition = {
          "StringEquals" : {
            "iam:ResourceTag/Project" : "GRC-Portfolio"
          }
        }
      },

      # Allow deleteing roles under /portfolio/ regradless of tags
      {
        Sid    = "IamDeletePortfolioRoles"
        Effect = "Allow"
        Action = [
          "iam:DeleteRole",
          "iam:DeleteRolePolicy"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/*"

      },



      # Allow IAM Manage for portfolio roles only
      {
        Sid    = "IamManagePortfolioRoles"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:UpdateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy"


        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/*"
        Condition = {
          "StringEquals" : {
            "iam:ResourceTag/Project" : "GRC-Portfolio"
          },

        }

      },

      # Allow WAF to create its service-linked role for logging
      {
        Sid      = "IamCreateWAFv2LoggingSLR"
        Effect   = "Allow"
        Action   = "iam:CreateServiceLinkedRole"
        Resource = "*"
        Condition = {
          "StringEquals" = {
            "iam:AWSServiceName" = "wafv2.amazonaws.com"
          }
        }
      },

      {
        Sid    = "IamDeleteWAFv2LoggingSLR"
        Effect = "Allow"
        Action = [
          "iam:DeleteServiceLinkedRole",
          "iam:GetServiceLinkedRoleDeletionStatus"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/logging.wafv2.amazonaws.com/AWSServiceRoleForWAFV2Logging"
      },


      {
        Sid      = "IamCreateManagedPolicies"
        Effect   = "Allow"
        Action   = ["iam:CreatePolicy", "iam:TagPolicy", "iam:GetPolicy"]
        Resource = "*"
        Condition = {
          "StringEquals" = {
            "aws:RequestTag/Project" = "GRC-Portfolio"
          }
        }

      },

      # List instance profiles for Roles
      {
        Sid    = "IamListInstanceProfiles"
        Effect = "Allow"
        Action = [
          "iam:ListInstanceProfilesForRole"
        ]
        Resource = ["*"]

      },

      # Allow instance profile operations
      {
        Sid    = "IamInstanceProfileOperations"
        Effect = "Allow"
        Action = [
          "iam:ListInstanceProfiles",
          "iam:GetInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:CreateInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:TagInstanceProfile"
        ]

        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*"
        ]
      },

      # Allow services to use the role
      {
        Sid    = "IamPassPortfolioRolesToServices"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/kms_lambda_exec_role",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/lambda_exec_role",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/lambda_incident_response_exec_role",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/s3-config-role",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/waf-firehose-role",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/EventBridge-Invoke-Lambda-Role"


        ]
        Condition = {
          "ForAnyValue:StringEquals" : {
            "iam:PassedToService" : [
              "lambda.amazonaws.com",
              "events.amazonaws.com",
              "config.amazonaws.com",
              "firehose.amazonaws.com"
            ]
          }
        }
      },

      # Allow EC2 to use the role
      {
        Sid    = "IamPassPortfolioRolesToEC2"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/portfolio/grc-app-instance-role-*"
        ]
    
      }


    ]
  })
}

# Terraform exec s3 permissions 
resource "aws_iam_policy" "terraform_exec_s3" {
  name        = "TerraformExecS3Permissions"
  description = "S3 permissions for Terraform execution role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Allow S3 Management for specific buckets
      {
        Sid    = "S3Management"
        Effect = "Allow"
        Action = [
          "s3:DeleteBucket",
          "s3:GetBucketEncryption",
          "s3:GetBucketLifecycleConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketTagging",
          "s3:GetBucketLogging",
          "s3:GetBucketVersioning",
          "s3:GetBucketOwnershipControls",
          "s3:GetPublicAccessBlock",
          "s3:GetBucketPolicy",
          "s3:GetBucketLocation",
          "s3:ListBucket",
          "s3:GetBucketAcl",
          "s3:GetBucketCORS",
          "s3:GetBucketWebsite",
          "s3:GetAccelerateConfiguration",
          "s3:GetBucketRequestPayment",
          "s3:GetReplicationConfiguration",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketNotification",
          "s3:DeleteBucketPolicy",
          "s3:ListBucketVersions"


        ]
        Resource = [
          "arn:aws:s3:::grc-encrypted-s3-bucket-test-${data.aws_caller_identity.current.account_id}",
          "arn:aws:s3:::my-encrypted-logs-test",
          "arn:aws:s3:::s3-tagging-config-delivery-test-${data.aws_caller_identity.current.account_id}",
          "arn:aws:s3:::alb-encrypted-logs-test-us-east-1",
          "arn:aws:s3:::waf-logs-test-${data.aws_caller_identity.current.account_id}"
        ]

      },

      # Object level actions
      {
        Sid    = "S3ObjectReadWriteDelete"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:DeleteObjectVersion",
          "s3:DeleteObject",
          "s3:DeleteObjectTagging",
          "s3:DeleteObjectVersionTagging"
        ]
        Resource = [
          "arn:aws:s3:::grc-encrypted-s3-bucket-test-${data.aws_caller_identity.current.account_id}/*",
          "arn:aws:s3:::my-encrypted-logs-test/*",
          "arn:aws:s3:::s3-tagging-config-delivery-test-${data.aws_caller_identity.current.account_id}/*",
          "arn:aws:s3:::alb-encrypted-logs-test-us-east-1/*",
          "arn:aws:s3:::waf-logs-test-${data.aws_caller_identity.current.account_id}/*"
        ]
      },

      # Allow S3 Create Management with tagging requirement
      {
        Sid    = "S3CreateManagement"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:PutBucketEncryption",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPolicy",
          "s3:PutBucketTagging",
          "s3:PutBucketLifecycle",
          "s3:PutBucketLifecycleConfiguration",
          "s3:PutBucketVersioning",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketLogging",
          "s3:ListBucket",
          "s3:PutBucketOwnershipControls",
          "s3:PutBucketNotification",
          "s3:PutLifecycleConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::grc-encrypted-s3-bucket-test-${data.aws_caller_identity.current.account_id}",
          "arn:aws:s3:::my-encrypted-logs-test",
          "arn:aws:s3:::s3-tagging-config-delivery-test-${data.aws_caller_identity.current.account_id}",
          "arn:aws:s3:::alb-encrypted-logs-test-us-east-1",
          "arn:aws:s3:::waf-logs-test-${data.aws_caller_identity.current.account_id}"
        ]


      },

      # Allow s3 Tagging
      {
        Sid    = "S3TaggingManagement"
        Effect = "Allow"
        Action = [
          "s3:PutBucketTagging",
          "s3:GetBucketTagging"
        ]

        Resource = [
          "arn:aws:s3:::grc-encrypted-s3-bucket-test-${data.aws_caller_identity.current.account_id}",
          "arn:aws:s3:::my-encrypted-logs-test",
          "arn:aws:s3:::s3-tagging-config-delivery-test-${data.aws_caller_identity.current.account_id}",
          "arn:aws:s3:::alb-encrypted-logs-test-us-east-1",
          "arn:aws:s3:::waf-logs-test-${data.aws_caller_identity.current.account_id}"
        ]
      }


    ]
  })
}

# Terraform exec ec2 permissions
resource "aws_iam_policy" "terraform_exec_ec2" {
  name        = "TerraformExecEc2Permissions"
  description = "Ec2 Permissions for Terraform execution role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow EC2 Management
      {
        Sid    = "AllowEc2Management"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeAddresses",
          "ec2:DescribeSubnets",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeAddressesAttribute",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeRouteTables",
          "ec2:DescribeNatGateways",
          "ec2:DisassociateRouteTable",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteRouteTable",
          "ec2:DeleteSubnet",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteNatGateway",
          "ec2:DetachInternetGateway",
          "ec2:DisassociateAddress",
          "ec2:ReleaseAddress",
          "ec2:DeleteInternetGateway",
          "ec2:DeleteVpc",
          "ec2:CreateVpc",
          "ec2:AllocateAddress",
          "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet",
          "ec2:CreateInternetGateway",
          "ec2:CreateSecurityGroup",
          "ec2:ModifySubnetAttribute",
          "ec2:AttachInternetGateway",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateRouteTable",
          "ec2:CreateNatGateway",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:CreateRoute",
          "ec2:AssociateRouteTable",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeKeyPairs",
          "ec2:RunInstance",
          "ec2:StartInstance",
          "ec2:GetConsoleOutput",
          "ec2:GetEbsDefaultKmsKeyId",
          "ec2:GetEbsEncryptionByDefault",
          "ec2:CreateSnapshot",
          "ec2:DescribeSnapshots"
      
        ]
        Resource = "*"
      },

      # Allow Creating initial Project tag on Ec2 resources
      {
        Sid    = "Ec2BootstrapProjectTag"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = "*"
        Condition = {
          "StringEquals" : {
            "aws:RequestTag/Project" : "GRC-Portfolio"
          }
        }
      },

      # Allow create/delete tags on resources that already carry Project=GRC-Portfolio
      {
        Sid    = "Ec2TaggingOnPortfolioResources"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
        Condition = {
          "StringEquals" : {
            "aws:ResourceTag/Project" : "GRC-Portfolio"
          }
        }
      }
    ]
  })
}


# Terraform exec ELB permissions 
resource "aws_iam_policy" "terraform_exec_elb" {
  name        = "TerraformExecElbPermissions"
  description = "Elb Permissions for Terraform execution role"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow ELB Management
      {
        Sid    = "ElasticLoadBalancerManagement"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:CreateTargetGroup",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:DeleteRule",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:RemoveTags",
          "elasticloadbalancing:DescribeTags",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeListenerAttributes",
          "elasticloadbalancing:SetWebACL"

        ]
        Resource = "*"
      },
    ]

  })
}

# Terraform exec autoscaling group
resource "aws_iam_policy" "terraform_exec_asg" {
  name        = "TerraformExecAutoscalingPermissions"
  description = "This permissions allow terraform manage ASG, launch template and scaling policies"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Auto Scaling Groups + Policies
      {
        Sid    = "AutoscalingManagement"
        Effect = "Allow"
        Action = [
          "autoscaling:CreateAutoScalingGroup",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DeleteAutoScalingGroup",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:CreateOrUpdateTags",
          "autoscaling:DeleteTags",
          "autoscaling:DescribeTags",
          "autoscaling:PutScalingPolicy",
          "autoscaling:DeletePolicy",
          "autoscaling:DescribePolicies",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:AttachLoadBalancerTargetGroups",
          "autoscaling:DetachLoadBalancerTargetGroups",
          "autoscaling:DescribeScalingActivities",
          "autoscaling:AttachInstances",
          "autoscaling:DetachInstances"
        ]
        Resource = ["*"]
      },

      # Allow creating the Auto Scaling SLR
      {
        Sid    = "IamCreateSLRForAutoScaling"
        Effect = "Allow"
        Action = [
          "iam:CreateServiceLinkedRole"
        ]
        Resource = ["*"]
        Condition = {
          "StringEquals" : {
            "iam:AWSServiceName" : "autoscaling.amazonaws.com"
          }
        }
      },

      # Allow deleting the Auto Scaling SLR
      {
        Sid    = "IamDeleteSLRForAutoScaling"
        Effect = "Allow"
        Action = [
          "iam:DeleteServiceLinkedRole",
          "iam:GetServiceLinkedRoleDeletionStatus",
          "iam:GetRole"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
      },

      # Launch templates
      {
        Sid    = "LaunchTemplateManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:ModifyLaunchTemplate"
        ]
        Resource = ["*"]
      },

      # Allow use Launch templates
      {
        Sid    = "AllowUseLaunchTemplate"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:launch-template/lt-0857f3b7a1c8e4a57"

        ]
      },


      {
        Sid    = "AllowEC2ResourceCreation"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:network-interface/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:key-pair/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:security-group/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:subnet/*"

        ]
      },

      # Allow use Launch templates
      {
        Sid    = "AllowDescribeLaunchTemplate"
        Effect = "Allow"
        Action = [
          "ec2:DescribeLaunchTemplateVersions"
        ]
        Resource = [
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:launch-template/lt-0857f3b7a1c8e4a57"

        ]
      },

      {
        Sid    = "AllowAutoScalingUseLaunchTemplate"
        Effect = "Allow"
        Action = [
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions"
        ]
        Resource = ["*"]
      },

      {
        Sid    = "AllowAutoScalingLaunchTemplateUsage"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateTags"
        ]
        Resource = [
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:launch-template/lt-0857f3b7a1c8e4a57",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:network-interface/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:key-pair/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:security-group/*",
          "arn:aws:ec2:us-east-1:${data.aws_caller_identity.current.account_id}:subnet/*"

        ]
      },

      # Allow Iam pass role to Auto Scaling 
      {
        Sid    = "IamPassRoleToAutoScaling"
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        Condition = {
          "StringEquals" : {
            "iam:PassedToService" : "autoscaling.amazonaws.com"
          }
        }
      },

      # Allow Iam pass role to Auto Scaling 
      {
        Sid    = "AllowAutoScalingFullLaunchTemplateAccess"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplatesVersions"
        ]
        Resource = "*"

      }


    ]
  })
}

# Terraform exec other services permissions 
resource "aws_iam_policy" "terraform_exec_services" {
  name        = "TerraformExecOtherServicesPermissions"
  description = "Other AWS services permissions for Terraform execution role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow KMSManagement
      {
        Sid    = "KMSManagement"
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:PutKeyPolicy",
          "kms:EnableKeyRotation",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
          "kms:ListResourceTags",
          "kms:TagResource",
          "kms:GetKeyRotationStatus",
          "kms:CreateAlias",
          "kms:UpdateAlias",
          "kms:DeleteAlias",
          "kms:ListAliases",
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
          "kms:RetireGrant",
          "kms:ListKeyPolicies",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext"


        ]
        Resource = "*"
      },

      # Allow Route53 Management
      {
        Sid    = "AllowRoute53Management"
        Effect = "Allow"
        Action = [
          "route53:ListHostedZones",
          "route53:GetHostedZone",
          "route53:ListTagsForResource",
          "route53:ListResourceRecordSets",
          "route53:ChangeResourceRecordSets",
          "route53:GetChange"

        ]
        Resource = "*"
      },

      # Allow SNS Management
      {
        Sid    = "AllowSNSManagement"
        Effect = "Allow"
        Action = [
          "sns:GetTopicAttributes",
          "sns:ListTagsForResource",
          "sns:GetSubscriptionAttributes",
          "sns:Subscribe",
          "sns:TagResource",
          "sns:Unsubscribe",
          "sns:DeleteTopic",
          "sns:CreateTopic",
          "sns:SetTopicAttributes"

        ]
        Resource = [
          "arn:aws:sns:us-east-1:${data.aws_caller_identity.current.account_id}:grc-critical-alerts",
          "arn:aws:sns:us-east-1:${data.aws_caller_identity.current.account_id}:waf-compliance-alerts"
        ]

      },

      # Allow Organization Management
      {
        Sid    = "AllowOrganizationManagement"
        Effect = "Allow"
        Action = [
          "organizations:DescribeOrganization",
          "organizations:DescribePolicy",
          "organizations:ListTagsForResource",
          "organizations:ListAccounts",
          "organizations:ListRoots",
          "organizations:ListAWSServiceAccessForOrganization",
          "organizations:ListTargetsForPolicy",
          "organizations:TagResource",
          "organizations:DetachPolicy",
          "organizations:DeletePolicy",
          "organizations:CreatePolicy",
          "organizations:AttachPolicy"
        ]
        Resource = "*"
      },

      # Allow EventBridge Management
      {
        Sid    = "AllowEventBridgeManagement"
        Effect = "Allow"
        Action = [
          "events:DescribeRule",
          "events:ListTagsForResource",
          "events:ListTargetsByRule",
          "events:TagResource",
          "events:RemoveTargets",
          "events:DeleteRule",
          "events:PutRule",
          "events:PutTargets"

        ]
        Resource = [
          "arn:aws:events:us-east-1:${data.aws_caller_identity.current.account_id}:rule/KMS-key-rotation-check",
          "arn:aws:events:us-east-1:${data.aws_caller_identity.current.account_id}:rule/guardduty-ec2-compromise-finding"
        ]
      },

      # Allow ACM Management
      {
        Sid    = "AllowACMManagement"
        Effect = "Allow"
        Action = [
          "acm:DescribeCertificate",
          "acm:ListTagsForCertificate",
          "acm:AddTagsToCertificate",
          "acm:DeleteCertificate",
          "acm:RequestCertificate"

        ]
        Resource = ["arn:aws:acm:us-east-1:${data.aws_caller_identity.current.account_id}:certificate/*"]
      },

      # Allow Lambda Management
      {
        Sid    = "AllowLamdaManagement"
        Effect = "Allow"
        Action = [
          "lambda:GetFunction",
          "lambda:ListVersionsByFunction",
          "lambda:GetFunctionCodeSigningConfig",
          "lambda:GetPolicy",
          "lambda:UpdateFunctionConfiguration",
          "lambda:TagResource",
          "lambda:RemovePermission",
          "lambda:DeleteFunction",
          "lambda:CreateFunction",
          "lambda:AddPermission",
          "lambda:UpdateFunctionCode"


        ]
        Resource = [
          "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:kms-key-compliance-checker",
          "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:s3-encryption-compliance-checker",
          "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:compromised_ec2_response",
        ]
      },

      # Allow Config Management
      {
        Sid    = "AllowConfigManagement"
        Effect = "Allow"
        Action = [
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigRules",
          "config:ListTagsForResource",
          "config:DescribeDeliveryChannels",
          "config:DescribeConfigurationRecorderStatus",
          "config:PutConfigurationRecorder",
          "config:TagResource",
          "config:DeleteConfigRule",
          "config:StopConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:DeleteConfigurationRecorder",
          "config:PutDeliveryChannel",
          "config:PutConfigRule",
          "config:StartConfigurationRecorder"
        ]
        Resource = "*"
      },

      # Allow Cloudwatch Management
      {
        Sid    = "AllowCloudWatchManagement"
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms",
          "cloudwatch:ListTagsForResource",
          "cloudwatch:TagResource",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:PutMetricAlarm"
        ]
        Resource = [
          "arn:aws:cloudwatch:us-east-1:${data.aws_caller_identity.current.account_id}:alarm:s3-encryption-critical-findings",
          "arn:aws:cloudwatch:us-east-1:${data.aws_caller_identity.current.account_id}:alarm:s3-encryption-failed-remediations",
          "arn:aws:cloudwatch:us-east-1:${data.aws_caller_identity.current.account_id}:alarm:WAF-BlockedRequests-Spike",
          "arn:aws:cloudwatch:us-east-1:${data.aws_caller_identity.current.account_id}:alarm:WAF-RateLimit-Triggered",
          "arn:aws:cloudwatch:us-east-1:${data.aws_caller_identity.current.account_id}:alarm:WAF-CommonRule-Count-High",
          "arn:aws:cloudwatch:us-east-1:${data.aws_caller_identity.current.account_id}:alarm:grc-app-high-cpu",
          "arn:aws:cloudwatch:us-east-1:${data.aws_caller_identity.current.account_id}:alarm:grc-app-low-cpu"
        ]
      },

      # Allow WAF Management
      {
        Sid    = "AllowWAFv2Management"
        Effect = "Allow"
        Action = [
          "wafv2:CreateWebACL",
          "wafv2:UpdateWebACL",
          "wafv2:GetWebACL",
          "wafv2:DeleteWebACL",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "wafv2:CreateWebACLLoggingConfiguration",
          "wafv2:GetWebACLLoggingConfiguration",
          "wafv2:DeleteWebACLLoggingConfiguration",
          "wafv2:ListLoggingConfigurations",
          "wafv2:TagResource",
          "wafv2:ListTagsForResource",
          "wafv2:GetWebACLForResource",
          "wafv2:PutLoggingConfiguration",
          "wafv2:GetLoggingConfiguration",
          "wafv2:DeleteLoggingConfiguration"

        ]
        Resource = ["*"]
      },


      # Allow Kinesis Management
      {
        Sid    = "AllowKinesisManagement"
        Effect = "Allow"
        Action = [
          "kinesis:CreateDeliveryStream",
          "kinesis:DescribeDeliveryStream",
          "kinesis:DeleteDeliveryStream",
          "kinesis:ListDeliveryStream",
          "kinesis:TagDeliveryStream",
          "kinesis:UpdateDeliveryStream"

        ]
        Resource = ["*"]
      },

      # Allow Firehose Management
      {
        Sid    = "AllowFirehoseManagement"
        Effect = "Allow"
        Action = [
          "firehose:TagDeliveryStream",
          "firehose:CreateDeliveryStream",
          "firehose:DescribeDeliveryStream",
          "firehose:ListTagsForDeliveryStream",
          "firehose:DeleteDeliveryStream"
        ]
        Resource = ["*"]
      }

    ]
  })
}
