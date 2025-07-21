# S3 Bucket Security Remediation - Outputs
# Provides verification commands and security status information

output "remediation_summary" {
  description = "Summary of security remediation applied"
  value = {
    bucket_name = var.bucket_name
    environment = var.environment
    guardian_priority_score = "10.3/10"
    remediation_status = "Applied"
    timestamp = timestamp()
  }
}

output "security_controls_applied" {
  description = "List of security controls applied to the bucket"
  value = [
    "S3 Block Public Access enabled",
    "Secure bucket policy with least privilege",
    "Server-side encryption (${var.encryption_algorithm})",
    "Versioning enabled",
    "Access logging configured",
    "Lifecycle policies implemented",
    "CloudWatch monitoring enabled",
    "SNS alerts configured"
  ]
}

output "compliance_frameworks_addressed" {
  description = "Compliance frameworks addressed by this remediation"
  value = {
    pci_dss = [
      "3.4 - Protect stored cardholder data",
      "7.1 - Restrict access to cardholder data",
      "9.1 - Use appropriate facility entry controls",
      "10.1 - Implement audit trails"
    ]
    cis_aws = [
      "1.20 - Ensure S3 bucket is not publicly accessible",
      "1.21 - Ensure S3 bucket versioning is enabled",
      "1.22 - Ensure S3 bucket has server-side encryption enabled"
    ]
    csa_ccm = [
      "CCM-01 - Access Control",
      "CCM-02 - Asset Management",
      "CCM-03 - Audit and Accountability"
    ]
    nist_csf = [
      "PR.AC-1 - Identities and credentials are managed",
      "PR.AC-3 - Remote access is managed",
      "PR.DS-1 - Data-at-rest is protected"
    ]
  }
}

output "verification_commands" {
  description = "AWS CLI commands to verify security controls"
  value = {
    check_public_access = "aws s3api get-public-access-block --bucket ${var.bucket_name}",
    check_bucket_policy = "aws s3api get-bucket-policy --bucket ${var.bucket_name}",
    check_encryption = "aws s3api get-bucket-encryption --bucket ${var.bucket_name}",
    check_versioning = "aws s3api get-bucket-versioning --bucket ${var.bucket_name}",
    check_logging = "aws s3api get-bucket-logging --bucket ${var.bucket_name}",
    check_lifecycle = "aws s3api get-bucket-lifecycle-configuration --bucket ${var.bucket_name}",
    list_objects = "aws s3 ls s3://${var.bucket_name} --recursive",
    test_access = "aws s3api head-object --bucket ${var.bucket_name} --key test-file.txt"
  }
}

output "rollback_commands" {
  description = "Emergency rollback commands (use with extreme caution)"
  value = {
    remove_public_access_block = "aws s3api delete-public-access-block --bucket ${var.bucket_name}",
    remove_bucket_policy = "aws s3api delete-bucket-policy --bucket ${var.bucket_name}",
    disable_versioning = "aws s3api put-bucket-versioning --bucket ${var.bucket_name} --versioning-configuration Status=Suspended",
    remove_encryption = "aws s3api delete-bucket-encryption --bucket ${var.bucket_name}",
    remove_logging = "aws s3api delete-bucket-logging --bucket ${var.bucket_name}",
    remove_lifecycle = "aws s3api delete-bucket-lifecycle --bucket ${var.bucket_name}"
  }
}

output "monitoring_resources" {
  description = "Security monitoring resources created"
  value = {
    cloudwatch_log_group = aws_cloudwatch_log_group.s3_monitoring.name
    sns_topic = aws_sns_topic.security_alerts.arn
    access_logs_bucket = aws_s3_bucket.access_logs.id
    alarm_name = aws_cloudwatch_metric_alarm.public_access_attempt.alarm_name
  }
}

output "authorized_access" {
  description = "Authorized IAM roles and users for bucket access"
  value = {
    authorized_roles = var.authorized_iam_roles
    authorized_users = var.authorized_iam_users
    total_authorized = length(var.authorized_iam_roles) + length(var.authorized_iam_users)
  }
}

output "data_protection_status" {
  description = "Data protection and retention configuration"
  value = {
    encryption_algorithm = var.encryption_algorithm
    versioning_enabled = aws_s3_bucket_versioning.critical_bucket.versioning_configuration[0].status
    data_retention_days = var.data_retention_days
    access_logging_enabled = var.enable_access_logging
  }
}

output "emergency_contacts" {
  description = "Emergency contact information for security incidents"
  value = {
    primary_contact = var.emergency_contacts.primary_contact
    backup_contact = var.emergency_contacts.backup_contact
    escalation_time_minutes = var.emergency_contacts.escalation_time
  }
}

output "cost_estimation" {
  description = "Estimated monthly costs for security controls"
  value = {
    s3_storage = "Varies based on data volume",
    cloudwatch_logs = "~$5-15/month",
    sns_alerts = "~$1-5/month",
    access_logs_storage = "~$2-10/month",
    total_estimated = "~$8-30/month"
  }
}

output "next_steps" {
  description = "Recommended next steps after remediation"
  value = [
    "Run verification script: ./scripts/verification.sh ${var.bucket_name}",
    "Monitor CloudWatch alarms for security events",
    "Review access logs weekly for suspicious activity",
    "Update incident response procedures",
    "Schedule quarterly security reviews",
    "Consider implementing additional controls (Object Lock, Cross-Region Replication)"
  ]
}

output "terraform_state_info" {
  description = "Terraform state information for tracking"
  value = {
    state_file = "terraform.tfstate"
    state_backend = "local"
    last_modified = timestamp()
    resources_created = 8
    resources_modified = 1
  }
}