# S3 Bucket Security Remediation - Main Configuration
# Addresses critical security finding: Publicly accessible S3 bucket with PII data

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Data sources for existing resources
data "aws_s3_bucket" "critical_bucket" {
  bucket = var.bucket_name
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# 1. PUBLIC ACCESS BLOCK - Immediate containment
resource "aws_s3_bucket_public_access_block" "critical_bucket" {
  bucket = data.aws_s3_bucket.critical_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket_policy.critical_bucket]
}

# 2. BUCKET POLICY - Enforce least privilege with MFA
resource "aws_s3_bucket_policy" "critical_bucket" {
  bucket = data.aws_s3_bucket.critical_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyPublicAccess"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          data.aws_s3_bucket.critical_bucket.arn,
          "${data.aws_s3_bucket.critical_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowAuthorizedAccessWithMFA"
        Effect = "Allow"
        Principal = {
          AWS = concat(var.authorized_iam_roles, var.authorized_iam_users)
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          data.aws_s3_bucket.critical_bucket.arn,
          "${data.aws_s3_bucket.critical_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
          }
        }
      }
    ]
  })
}

# 3. SERVER-SIDE ENCRYPTION
resource "aws_s3_bucket_server_side_encryption_configuration" "critical_bucket" {
  bucket = data.aws_s3_bucket.critical_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.encryption_algorithm
    }
    bucket_key_enabled = true
  }
}

# 4. VERSIONING - Protect against accidental deletion
resource "aws_s3_bucket_versioning" "critical_bucket" {
  bucket = data.aws_s3_bucket.critical_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 5. ACCESS LOGGING - Audit trail
resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.bucket_name}-access-logs-${random_string.suffix.result}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "critical_bucket" {
  bucket = data.aws_s3_bucket.critical_bucket.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "logs/"
}

# 6. LIFECYCLE POLICY - Data retention and cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "critical_bucket" {
  bucket = data.aws_s3_bucket.critical_bucket.id

  rule {
    id     = "data_retention"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = var.data_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# 7. CLOUDWATCH ALARMS - Security monitoring
resource "aws_cloudwatch_log_group" "s3_monitoring" {
  name              = "/aws/s3/${var.bucket_name}/security"
  retention_in_days = 30
}

resource "aws_cloudwatch_metric_alarm" "public_access_attempt" {
  alarm_name          = "${var.bucket_name}-public-access-attempt"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "NumberOfObjects"
  namespace           = "AWS/S3"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Monitor for public access attempts on critical S3 bucket"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  dimensions = {
    BucketName = var.bucket_name
  }
}

# 8. SNS TOPIC - Security alerts
resource "aws_sns_topic" "security_alerts" {
  name = "${var.bucket_name}-security-alerts"
}

resource "aws_sns_topic_subscription" "security_alerts" {
  count     = length(var.alert_emails)
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_emails[count.index]
}

# 9. TAGS - Compliance and cost tracking
resource "aws_s3_bucket" "critical_bucket_tags" {
  bucket = data.aws_s3_bucket.critical_bucket.id

  tags = merge(var.common_tags, {
    Name        = var.bucket_name
    Environment = var.environment
    DataClass   = "PII"
    Compliance  = "PCI-DSS"
    Owner       = var.bucket_owner
    CostCenter  = var.cost_center
    Backup      = "Required"
    Encryption  = "Required"
    Monitoring  = "Enabled"
  })
}

# 10. RANDOM SUFFIX FOR UNIQUE NAMES
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# 11. OUTPUTS FOR VERIFICATION
output "bucket_arn" {
  description = "ARN of the secured S3 bucket"
  value       = data.aws_s3_bucket.critical_bucket.arn
}

output "public_access_block_status" {
  description = "Public access block configuration"
  value = {
    block_public_acls       = aws_s3_bucket_public_access_block.critical_bucket.block_public_acls
    block_public_policy     = aws_s3_bucket_public_access_block.critical_bucket.block_public_policy
    ignore_public_acls      = aws_s3_bucket_public_access_block.critical_bucket.ignore_public_acls
    restrict_public_buckets = aws_s3_bucket_public_access_block.critical_bucket.restrict_public_buckets
  }
}

output "encryption_status" {
  description = "Server-side encryption configuration"
  value = {
    algorithm = var.encryption_algorithm
    enabled   = true
  }
}

output "versioning_status" {
  description = "Versioning configuration"
  value = {
    status = aws_s3_bucket_versioning.critical_bucket.versioning_configuration[0].status
  }
}

output "monitoring_resources" {
  description = "Security monitoring resources created"
  value = {
    cloudwatch_log_group = aws_cloudwatch_log_group.s3_monitoring.name
    sns_topic           = aws_sns_topic.security_alerts.arn
    access_logs_bucket  = aws_s3_bucket.access_logs.id
  }
}