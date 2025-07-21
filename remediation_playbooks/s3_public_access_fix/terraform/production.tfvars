# Production Configuration for S3 Bucket Security Remediation
# Critical Security Finding: Publicly accessible S3 bucket with PII data
# Guardian Priority Score: 10.3/10

# Core Configuration
bucket_name = "my-critical-data-prod"
environment = "prod"

# Authorized Access - Update with your actual IAM roles and users
authorized_iam_roles = [
  # Example: "arn:aws:iam::123456789012:role/DataAccessRole",
  # Example: "arn:aws:iam::123456789012:role/BackupServiceRole"
]

authorized_iam_users = [
  # Example: "arn:aws:iam::123456789012:user/data-admin",
  # Example: "arn:aws:iam::123456789012:user/security-admin"
]

# Security Configuration
encryption_algorithm = "AES256"
data_retention_days = 2555  # 7 years for PII data

# Monitoring and Alerts
alert_emails = [
  "security@company.com",
  "oncall@company.com",
  "compliance@company.com"
]

# Resource Ownership
bucket_owner = "security-team"
cost_center = "security"

# Common Tags
common_tags = {
  Project     = "Chimera-Core"
  Purpose     = "S3-Security-Remediation"
  ManagedBy   = "Terraform"
  Compliance  = "PCI-DSS"
  DataType    = "PII"
  Criticality = "Critical"
  BusinessUnit = "Security"
  DataRetention = "7-years"
  BackupRequired = "true"
  EncryptionRequired = "true"
  MonitoringEnabled = "true"
}

# Feature Flags
enable_monitoring = true
enable_access_logging = true
enable_versioning = true
enable_lifecycle_policies = true

# AWS Configuration
aws_region = "us-east-1"
force_destroy = false

# Emergency Contacts
emergency_contacts = {
  primary_contact = "security@company.com"
  backup_contact  = "oncall@company.com"
  escalation_time = 30  # minutes
}