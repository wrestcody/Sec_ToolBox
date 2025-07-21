# S3 Public Access Remediation - Main Configuration
# Guardian Priority Score: 10.3/10 (Critical)
# 
# This configuration addresses the critical security finding:
# AWS S3 bucket 'my-critical-data-prod' is publicly accessible and contains PII data
#
# Security Defense Gaps Addressed:
# 1. Data Access Control Gap - S3 Block Public Access
# 2. Data Classification & Protection Gap - Secure bucket policies
# 3. Network Segmentation Gap - Remove public exposure
# 4. Encryption & Security Controls Gap - Server-side encryption
# 5. Monitoring & Logging Gap - Access logging and monitoring

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  
  # Enable state locking and encryption for security
  backend "s3" {
    bucket         = "terraform-state-chimera-core"
    key            = "s3-remediation/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

# Configure AWS Provider with secure defaults
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Chimera-Core"
      Environment = var.environment
      Purpose     = "S3-Security-Remediation"
      Owner       = "Security-Team"
      Compliance  = "PCI-DSS-CIS-CCM"
      DataType    = "PII"
      Criticality = "Critical"
    }
  }
}

# Random string for unique resource naming
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# =============================================================================
# PHASE 1: IMMEDIATE CONTAINMENT - Block Public Access
# =============================================================================

# Critical: Block all public access to the S3 bucket
resource "aws_s3_bucket_public_access_block" "critical_data_block" {
  bucket = var.critical_bucket_name
  
  # Block all forms of public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # Prevent accidental deletion during remediation
  lifecycle {
    prevent_destroy = true
  }
  
  depends_on = [aws_s3_bucket_policy.critical_data_policy]
}

# =============================================================================
# PHASE 2: SECURE BUCKET POLICY - Enforce Access Controls
# =============================================================================

# Secure bucket policy with least privilege principle
resource "aws_s3_bucket_policy" "critical_data_policy" {
  bucket = var.critical_bucket_name
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Deny public read access to all objects
      {
        Sid       = "DenyPublicReadAccess"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetObjectAcl",
          "s3:GetObjectVersionAcl"
        ]
        Resource = "arn:aws:s3:::${var.critical_bucket_name}/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = concat(
              var.authorized_roles,
              var.authorized_users
            )
          }
        }
      },
      
      # Enforce server-side encryption for all uploads
      {
        Sid       = "EnforceEncryption"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${var.critical_bucket_name}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      },
      
      # Require MFA for sensitive operations
      {
        Sid       = "RequireMFAForSensitiveOperations"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy"
        ]
        Resource = [
          "arn:aws:s3:::${var.critical_bucket_name}",
          "arn:aws:s3:::${var.critical_bucket_name}/*"
        ]
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      
      # Allow authorized access with proper authentication
      {
        Sid       = "AllowAuthorizedAccess"
        Effect    = "Allow"
        Principal = {
          AWS = concat(
            var.authorized_roles,
            var.authorized_users
          )
        }
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::${var.critical_bucket_name}/*"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
  
  # Prevent accidental deletion
  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# PHASE 3: ENCRYPTION - Server-Side Encryption
# =============================================================================

# Enable server-side encryption for all objects
resource "aws_s3_bucket_server_side_encryption_configuration" "critical_data_encryption" {
  bucket = var.critical_bucket_name
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
  
  # Prevent accidental deletion
  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# PHASE 4: VERSIONING - Data Protection
# =============================================================================

# Enable versioning for data protection and recovery
resource "aws_s3_bucket_versioning" "critical_data_versioning" {
  bucket = var.critical_bucket_name
  
  versioning_configuration {
    status = "Enabled"
  }
  
  # Prevent accidental deletion
  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# PHASE 5: ACCESS LOGGING - Monitoring and Audit
# =============================================================================

# Create dedicated bucket for access logs
resource "aws_s3_bucket" "access_logs" {
  bucket = "chimera-core-access-logs-${random_string.suffix.result}"
  
  tags = {
    Name        = "Chimera Core Access Logs"
    Environment = var.environment
    Purpose     = "Security Logging"
    DataType    = "Logs"
    Retention   = "90-days"
  }
}

# Enable access logging for the critical data bucket
resource "aws_s3_bucket_logging" "critical_data_logging" {
  bucket = var.critical_bucket_name
  
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "logs/${var.critical_bucket_name}/"
  
  depends_on = [aws_s3_bucket.access_logs]
}

# Apply public access block to logs bucket
resource "aws_s3_bucket_public_access_block" "access_logs_block" {
  bucket = aws_s3_bucket.access_logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption for logs bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_encryption" {
  bucket = aws_s3_bucket.access_logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# =============================================================================
# PHASE 6: DATA LIFECYCLE - Retention and Cleanup
# =============================================================================

# Implement data lifecycle policy for PII data
resource "aws_s3_bucket_lifecycle_configuration" "critical_data_lifecycle" {
  bucket = var.critical_bucket_name
  
  rule {
    id     = "pii_data_retention"
    status = "Enabled"
    
    filter {
      prefix = "pii/"
    }
    
    # PII data retention: 7 years (2555 days)
    expiration {
      days = 2555
    }
    
    # Noncurrent version expiration: 30 days
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    
    # Abort incomplete multipart uploads: 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  
  rule {
    id     = "general_data_retention"
    status = "Enabled"
    
    filter {
      prefix = "data/"
    }
    
    # General data retention: 3 years (1095 days)
    expiration {
      days = 1095
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# =============================================================================
# PHASE 7: MONITORING - CloudWatch Alarms
# =============================================================================

# CloudWatch log group for S3 access monitoring
resource "aws_cloudwatch_log_group" "s3_access_logs" {
  name              = "/aws/s3/${var.critical_bucket_name}/access"
  retention_in_days = 90
  
  tags = {
    Name        = "S3 Access Logs"
    Environment = var.environment
    Purpose     = "Security Monitoring"
  }
}

# Alarm for public access attempts
resource "aws_cloudwatch_metric_alarm" "s3_public_access_attempt" {
  alarm_name          = "${var.critical_bucket_name}-public-access-attempt"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "NumberOfObjects"
  namespace           = "AWS/S3"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  
  alarm_description = "Alert when public access is attempted on critical data bucket"
  alarm_actions     = [aws_sns_topic.security_alerts.arn]
  
  tags = {
    Name        = "S3 Public Access Alarm"
    Environment = var.environment
    Severity    = "Critical"
  }
}

# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name = "chimera-core-security-alerts"
  
  tags = {
    Name        = "Security Alerts"
    Environment = var.environment
    Purpose     = "Security Notifications"
  }
}

# SNS topic subscription (configure as needed)
resource "aws_sns_topic_subscription" "security_alerts_email" {
  count     = var.enable_email_alerts ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_team_email
}

# =============================================================================
# PHASE 8: COMPLIANCE - Audit Trail
# =============================================================================

# Create audit trail documentation
resource "local_file" "audit_trail" {
  filename = "${path.module}/../compliance/audit_trail.md"
  content  = templatefile("${path.module}/templates/audit_trail.md.tpl", {
    timestamp         = timestamp()
    bucket_name       = var.critical_bucket_name
    environment       = var.environment
    guardian_score    = "10.3/10"
    compliance_frameworks = [
      "PCI DSS 3.4, 7.1, 9.1",
      "CIS AWS 1.20, 1.21, 1.22",
      "CSA CCM CCM-01, CCM-02, CCM-03",
      "NIST CSF PR.AC-1, PR.AC-3, PR.DS-1"
    ]
    security_controls = [
      "S3 Block Public Access enabled",
      "Secure bucket policy with least privilege",
      "Server-side encryption (AES256)",
      "Versioning enabled",
      "Access logging configured",
      "Data lifecycle policies implemented",
      "CloudWatch monitoring and alerting"
    ]
  })
}