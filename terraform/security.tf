# Security Hardening - CNAPP Best Practices Applied
# Based on: Checkmarx 15 CNAPP Best Practices, Wiz Security Graph, Gartner CNAPP Guide

# Best Practice 3: Principle of Least Privilege - Prowler scan role
resource "aws_iam_role" "prowler_scan" {
  name = "${var.project_name}-prowler-scan"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
  tags = var.tags
}

data "aws_caller_identity" "current" {}

# Read-only scanning policy (least privilege)
resource "aws_iam_role_policy" "prowler_scan" {
  name = "prowler-readonly-scan"
  role = aws_iam_role.prowler_scan.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityAuditReadOnly"
        Effect = "Allow"
        Action = [
          "access-analyzer:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:LookupEvents",
          "cloudwatch:Describe*",
          "config:Describe*",
          "ec2:Describe*",
          "iam:Get*",
          "iam:List*",
          "iam:GenerateCredentialReport",
          "kms:Describe*",
          "kms:List*",
          "lambda:Get*",
          "lambda:List*",
          "rds:Describe*",
          "s3:GetBucket*",
          "s3:GetEncryptionConfiguration",
          "s3:ListAllMyBuckets",
          "s3:ListBucket",
          "securityhub:Get*",
          "sns:List*",
          "sqs:List*",
          "ssm:Describe*",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
      {
        Sid    = "CWPPSnapshotScan"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:CreateTags",
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestTag/prowler:scan" = "cwpp" }
        }
      },
    ]
  })
}

# Best Practice 7: Encrypt Data at Rest and in Transit
# KMS key for encrypting CNAPP data
resource "aws_kms_key" "cnapp" {
  description             = "Prowler CNAPP encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "cnapp" {
  name          = "alias/${var.project_name}"
  target_key_id = aws_kms_key.cnapp.key_id
}

# Best Practice 4: Zero Trust - WAF for ALB
resource "aws_wafv2_web_acl" "main" {
  name        = var.project_name
  scope       = "REGIONAL"
  description = "WAF for Prowler CNAPP ALB"

  default_action {
    allow {}
  }

  # Rate limiting
  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-rate-limit"
    }
  }

  # Block known bad IPs
  rule {
    name     = "aws-managed-ip-reputation"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-ip-reputation"
    }
  }

  # SQL injection protection
  rule {
    name     = "aws-managed-sqli"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-sqli"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = var.project_name
  }

  tags = var.tags
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# Best Practice 5: Workload Segmentation - VPC Flow Logs
resource "aws_flow_log" "main" {
  vpc_id               = module.vpc.vpc_id
  traffic_type         = "ALL"
  iam_role_arn         = aws_iam_role.flow_log.arn
  log_destination      = aws_cloudwatch_log_group.flow_log.arn
  log_destination_type = "cloud-watch-logs"
  tags                 = var.tags
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/vpc/${var.project_name}/flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.cnapp.arn
  tags              = var.tags
}

resource "aws_iam_role" "flow_log" {
  name = "${var.project_name}-flow-log"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_log" {
  name = "flow-log-publish"
  role = aws_iam_role.flow_log.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "*"
    }]
  })
}

# Best Practice 10: Threat Intelligence - GuardDuty
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

# Best Practice 13: Compliance - AWS Config
resource "aws_config_configuration_recorder" "main" {
  name     = var.project_name
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = true
  }
}

resource "aws_iam_role" "config" {
  name = "${var.project_name}-config"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Best Practice 9: Behavior Analytics - CloudTrail for CDR
resource "aws_cloudtrail" "main" {
  name                          = var.project_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cnapp.arn
  tags                          = var.tags
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${var.project_name}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cnapp.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}
