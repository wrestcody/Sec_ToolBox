# Production Configuration for S3 Public Access Remediation
# Guardian Priority Score: 10.3/10 (Critical)
#
# This file contains production-specific variables for the S3 security remediation
# All values are configured for maximum security and compliance

# =============================================================================
# CORE CONFIGURATION
# =============================================================================

aws_region = "us-east-1"
environment = "production"
critical_bucket_name = "my-critical-data-prod"

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Authorized IAM roles that can access the critical bucket
# Replace with actual role ARNs from your environment
authorized_roles = [
  "arn:aws:iam::123456789012:role/DataAccessRole",
  "arn:aws:iam::123456789012:role/BackupServiceRole",
  "arn:aws:iam::123456789012:role/AnalyticsServiceRole"
]

# Authorized IAM users that can access the critical bucket
# Replace with actual user ARNs from your environment
authorized_users = [
  "arn:aws:iam::123456789012:user/data-admin",
  "arn:aws:iam::123456789012:user/security-admin"
]

# Enable MFA enforcement for all sensitive operations
enable_mfa_enforcement = true

# Use AES256 encryption for maximum compatibility
encryption_algorithm = "AES256"

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

# Enable email alerts for security events
enable_email_alerts = true
security_team_email = "security@chimera-core.com"

# Enable Slack alerts for real-time notifications
enable_slack_alerts = true
slack_webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Retain logs for 90 days for compliance
log_retention_days = 90

# =============================================================================
# DATA LIFECYCLE
# =============================================================================

# PII data retention: 7 years (2555 days) for compliance
pii_retention_days = 2555

# General data retention: 3 years (1095 days)
general_data_retention_days = 1095

# Noncurrent version retention: 30 days
noncurrent_version_retention_days = 30

# Abort incomplete multipart uploads after 7 days
incomplete_multipart_upload_days = 7

# =============================================================================
# COMPLIANCE AND TAGGING
# =============================================================================

# Compliance frameworks addressed by this remediation
compliance_frameworks = [
  "PCI-DSS",
  "CIS-AWS",
  "CSA-CCM",
  "NIST-CSF",
  "HIPAA"
]

# Data classification level
data_classification = "PII"

# Business unit responsible for the data
business_unit = "Security"

# Cost center for resource billing
cost_center = "SEC-001"

# =============================================================================
# ADVANCED CONFIGURATION
# =============================================================================

# Disable cross-account access for maximum security
enable_cross_account_access = false
cross_account_roles = []

# Enable bucket key for encryption performance
enable_bucket_key = true

# Disable intelligent tiering to maintain data accessibility
enable_intelligent_tiering = false

# Enable object lock for compliance requirements
enable_object_lock = true
object_lock_retention_days = 2555

# =============================================================================
# EMERGENCY CONTACTS
# =============================================================================

# Emergency contact information
emergency_contact_name = "Security Team Lead"
emergency_contact_phone = "+1-555-0123"
emergency_contact_email = "emergency@chimera-core.com"