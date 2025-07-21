# S3 Public Access Remediation - Outputs
# 
# This file defines all outputs from the S3 security remediation
# Outputs provide important information for verification and monitoring

# =============================================================================
# CORE RESOURCE OUTPUTS
# =============================================================================

output "critical_bucket_name" {
  description = "Name of the critical S3 bucket that was remediated"
  value       = var.critical_bucket_name
}

output "critical_bucket_arn" {
  description = "ARN of the critical S3 bucket"
  value       = "arn:aws:s3:::${var.critical_bucket_name}"
}

output "access_logs_bucket_name" {
  description = "Name of the access logs bucket"
  value       = aws_s3_bucket.access_logs.id
}

output "access_logs_bucket_arn" {
  description = "ARN of the access logs bucket"
  value       = aws_s3_bucket.access_logs.arn
}

# =============================================================================
# SECURITY STATUS OUTPUTS
# =============================================================================

output "public_access_block_status" {
  description = "Status of S3 Block Public Access settings"
  value = {
    block_public_acls       = aws_s3_bucket_public_access_block.critical_data_block.block_public_acls
    block_public_policy     = aws_s3_bucket_public_access_block.critical_data_block.block_public_policy
    ignore_public_acls      = aws_s3_bucket_public_access_block.critical_data_block.ignore_public_acls
    restrict_public_buckets = aws_s3_bucket_public_access_block.critical_data_block.restrict_public_buckets
  }
}

output "encryption_status" {
  description = "Status of server-side encryption configuration"
  value = {
    algorithm = aws_s3_bucket_server_side_encryption_configuration.critical_data_encryption.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm
    bucket_key_enabled = aws_s3_bucket_server_side_encryption_configuration.critical_data_encryption.rule[0].bucket_key_enabled
  }
}

output "versioning_status" {
  description = "Status of S3 bucket versioning"
  value = {
    status = aws_s3_bucket_versioning.critical_data_versioning.versioning_configuration[0].status
  }
}

output "access_logging_status" {
  description = "Status of S3 access logging configuration"
  value = {
    target_bucket = aws_s3_bucket_logging.critical_data_logging.target_bucket
    target_prefix = aws_s3_bucket_logging.critical_data_logging.target_prefix
  }
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for S3 access monitoring"
  value       = aws_cloudwatch_log_group.s3_access_logs.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.s3_access_logs.arn
}

output "security_alarm_name" {
  description = "Name of the CloudWatch alarm for public access attempts"
  value       = aws_cloudwatch_metric_alarm.s3_public_access_attempt.alarm_name
}

output "security_alarm_arn" {
  description = "ARN of the CloudWatch alarm"
  value       = aws_cloudwatch_metric_alarm.s3_public_access_attempt.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

# =============================================================================
# COMPLIANCE OUTPUTS
# =============================================================================

output "compliance_frameworks_addressed" {
  description = "List of compliance frameworks addressed by this remediation"
  value       = var.compliance_frameworks
}

output "data_classification" {
  description = "Data classification level of the remediated bucket"
  value       = var.data_classification
}

output "guardian_priority_score" {
  description = "Guardian Priority Score for this security finding"
  value       = "10.3/10 (Critical)"
}

output "security_controls_implemented" {
  description = "List of security controls implemented"
  value = [
    "S3 Block Public Access enabled",
    "Secure bucket policy with least privilege",
    "Server-side encryption (AES256)",
    "Versioning enabled",
    "Access logging configured",
    "Data lifecycle policies implemented",
    "CloudWatch monitoring and alerting",
    "MFA enforcement for sensitive operations"
  ]
}

# =============================================================================
# VERIFICATION OUTPUTS
# =============================================================================

output "verification_commands" {
  description = "Commands to verify the remediation was successful"
  value = {
    check_public_access = "aws s3api get-public-access-block --bucket ${var.critical_bucket_name}",
    check_encryption = "aws s3api get-bucket-encryption --bucket ${var.critical_bucket_name}",
    check_versioning = "aws s3api get-bucket-versioning --bucket ${var.critical_bucket_name}",
    check_logging = "aws s3api get-bucket-logging --bucket ${var.critical_bucket_name}",
    check_policy = "aws s3api get-bucket-policy --bucket ${var.critical_bucket_name}",
    test_public_access = "aws s3 ls s3://${var.critical_bucket_name} --no-sign-request"
  }
}

output "rollback_commands" {
  description = "Emergency rollback commands (use only if service disruption occurs)"
  value = {
    remove_public_access_block = "aws s3api put-public-access-block --bucket ${var.critical_bucket_name} --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false",
    remove_bucket_policy = "aws s3api delete-bucket-policy --bucket ${var.critical_bucket_name}",
    remove_encryption = "aws s3api delete-bucket-encryption --bucket ${var.critical_bucket_name}"
  }
  sensitive = true
}

# =============================================================================
# COST AND RESOURCE OUTPUTS
# =============================================================================

output "estimated_monthly_cost" {
  description = "Estimated monthly cost for the remediation resources"
  value = {
    s3_storage = "Varies based on data volume",
    cloudwatch_logs = "~$5-15/month",
    sns_alerts = "~$1-5/month",
    total_estimate = "$6-20/month"
  }
}

output "resource_tags" {
  description = "Tags applied to all resources for cost tracking and compliance"
  value = {
    Project     = "Chimera-Core"
    Environment = var.environment
    Purpose     = "S3-Security-Remediation"
    Owner       = "Security-Team"
    Compliance  = "PCI-DSS-CIS-CCM"
    DataType    = "PII"
    Criticality = "Critical"
    BusinessUnit = var.business_unit
    CostCenter  = var.cost_center
  }
}

# =============================================================================
# EMERGENCY CONTACT OUTPUTS
# =============================================================================

output "emergency_contacts" {
  description = "Emergency contact information for security incidents"
  value = {
    name  = var.emergency_contact_name
    phone = var.emergency_contact_phone
    email = var.emergency_contact_email
  }
  sensitive = true
}

# =============================================================================
# DEPENDENCIES OUTPUTS
# =============================================================================

output "resource_dependencies" {
  description = "List of resource dependencies for this remediation"
  value = [
    "AWS S3 bucket: ${var.critical_bucket_name}",
    "AWS S3 bucket: ${aws_s3_bucket.access_logs.id}",
    "CloudWatch log group: ${aws_cloudwatch_log_group.s3_access_logs.name}",
    "CloudWatch alarm: ${aws_cloudwatch_metric_alarm.s3_public_access_attempt.alarm_name}",
    "SNS topic: ${aws_sns_topic.security_alerts.name}"
  ]
}

output "required_permissions" {
  description = "Required AWS permissions for this remediation"
  value = [
    "s3:GetBucketPublicAccessBlock",
    "s3:PutBucketPublicAccessBlock",
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:GetBucketEncryption",
    "s3:PutBucketEncryption",
    "s3:DeleteBucketEncryption",
    "s3:GetBucketVersioning",
    "s3:PutBucketVersioning",
    "s3:GetBucketLogging",
    "s3:PutBucketLogging",
    "s3:GetBucketLifecycleConfiguration",
    "s3:PutBucketLifecycleConfiguration",
    "logs:CreateLogGroup",
    "logs:PutRetentionPolicy",
    "cloudwatch:PutMetricAlarm",
    "sns:CreateTopic",
    "sns:Subscribe"
  ]
}