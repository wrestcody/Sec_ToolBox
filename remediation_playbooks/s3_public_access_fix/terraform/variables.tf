# S3 Public Access Remediation - Variables
# 
# This file defines all variables used in the S3 security remediation
# All variables include secure defaults and validation rules

# =============================================================================
# CORE CONFIGURATION VARIABLES
# =============================================================================

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "AWS region must be in the format 'us-east-1', 'eu-west-1', etc."
  }
}

variable "environment" {
  description = "Environment name (e.g., production, staging, development)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be one of: production, staging, development."
  }
}

variable "critical_bucket_name" {
  description = "Name of the critical S3 bucket that needs remediation"
  type        = string
  default     = "my-critical-data-prod"
  
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.critical_bucket_name))
    error_message = "Bucket name must be between 3 and 63 characters, contain only lowercase letters, numbers, dots, and hyphens, and start/end with a letter or number."
  }
}

# =============================================================================
# SECURITY CONFIGURATION VARIABLES
# =============================================================================

variable "authorized_roles" {
  description = "List of IAM role ARNs authorized to access the critical bucket"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for role in var.authorized_roles : can(regex("^arn:aws:iam::[0-9]{12}:role/", role))
    ])
    error_message = "All authorized roles must be valid IAM role ARNs."
  }
}

variable "authorized_users" {
  description = "List of IAM user ARNs authorized to access the critical bucket"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for user in var.authorized_users : can(regex("^arn:aws:iam::[0-9]{12}:user/", user))
    ])
    error_message = "All authorized users must be valid IAM user ARNs."
  }
}

variable "enable_mfa_enforcement" {
  description = "Enable MFA enforcement for sensitive operations"
  type        = bool
  default     = true
}

variable "encryption_algorithm" {
  description = "Server-side encryption algorithm to use"
  type        = string
  default     = "AES256"
  
  validation {
    condition     = contains(["AES256", "aws:kms"], var.encryption_algorithm)
    error_message = "Encryption algorithm must be either 'AES256' or 'aws:kms'."
  }
}

variable "kms_key_id" {
  description = "KMS key ID for server-side encryption (required if encryption_algorithm is 'aws:kms')"
  type        = string
  default     = null
  
  validation {
    condition = var.encryption_algorithm != "aws:kms" || (
      var.kms_key_id != null && can(regex("^arn:aws:kms:", var.kms_key_id))
    )
    error_message = "KMS key ID must be provided and be a valid KMS key ARN when using 'aws:kms' encryption."
  }
}

# =============================================================================
# MONITORING AND ALERTING VARIABLES
# =============================================================================

variable "enable_email_alerts" {
  description = "Enable email alerts for security events"
  type        = bool
  default     = true
}

variable "security_team_email" {
  description = "Email address for security team alerts"
  type        = string
  default     = "security@chimera-core.com"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.security_team_email))
    error_message = "Security team email must be a valid email address."
  }
}

variable "enable_slack_alerts" {
  description = "Enable Slack alerts for security events"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for security alerts"
  type        = string
  default     = ""
  sensitive   = true
  
  validation {
    condition = !var.enable_slack_alerts || (
      var.slack_webhook_url != "" && can(regex("^https://hooks.slack.com/", var.slack_webhook_url))
    )
    error_message = "Slack webhook URL must be provided and be a valid Slack webhook URL when Slack alerts are enabled."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 90
  
  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 3653
    error_message = "Log retention days must be between 1 and 3653."
  }
}

# =============================================================================
# DATA LIFECYCLE VARIABLES
# =============================================================================

variable "pii_retention_days" {
  description = "Number of days to retain PII data"
  type        = number
  default     = 2555  # 7 years
  
  validation {
    condition     = var.pii_retention_days >= 365 && var.pii_retention_days <= 3650
    error_message = "PII retention days must be between 365 and 3650 days."
  }
}

variable "general_data_retention_days" {
  description = "Number of days to retain general data"
  type        = number
  default     = 1095  # 3 years
  
  validation {
    condition     = var.general_data_retention_days >= 30 && var.general_data_retention_days <= 1825
    error_message = "General data retention days must be between 30 and 1825 days."
  }
}

variable "noncurrent_version_retention_days" {
  description = "Number of days to retain noncurrent versions"
  type        = number
  default     = 30
  
  validation {
    condition     = var.noncurrent_version_retention_days >= 1 && var.noncurrent_version_retention_days <= 365
    error_message = "Noncurrent version retention days must be between 1 and 365 days."
  }
}

variable "incomplete_multipart_upload_days" {
  description = "Number of days after which incomplete multipart uploads are aborted"
  type        = number
  default     = 7
  
  validation {
    condition     = var.incomplete_multipart_upload_days >= 1 && var.incomplete_multipart_upload_days <= 30
    error_message = "Incomplete multipart upload days must be between 1 and 30 days."
  }
}

# =============================================================================
# COMPLIANCE AND TAGGING VARIABLES
# =============================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks this remediation addresses"
  type        = list(string)
  default = [
    "PCI-DSS",
    "CIS-AWS",
    "CSA-CCM",
    "NIST-CSF"
  ]
  
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks : contains([
        "PCI-DSS", "CIS-AWS", "CSA-CCM", "NIST-CSF", "HIPAA", "SOC2", "ISO27001"
      ], framework)
    ])
    error_message = "Compliance framework must be one of: PCI-DSS, CIS-AWS, CSA-CCM, NIST-CSF, HIPAA, SOC2, ISO27001."
  }
}

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "PII"
  
  validation {
    condition     = contains(["PII", "PHI", "PCI", "CONFIDENTIAL", "INTERNAL", "PUBLIC"], var.data_classification)
    error_message = "Data classification must be one of: PII, PHI, PCI, CONFIDENTIAL, INTERNAL, PUBLIC."
  }
}

variable "business_unit" {
  description = "Business unit responsible for the data"
  type        = string
  default     = "Security"
  
  validation {
    condition     = length(var.business_unit) >= 2 && length(var.business_unit) <= 50
    error_message = "Business unit must be between 2 and 50 characters."
  }
}

variable "cost_center" {
  description = "Cost center for resource billing"
  type        = string
  default     = "SEC-001"
  
  validation {
    condition     = can(regex("^[A-Z0-9-]+$", var.cost_center))
    error_message = "Cost center must contain only uppercase letters, numbers, and hyphens."
  }
}

# =============================================================================
# ADVANCED CONFIGURATION VARIABLES
# =============================================================================

variable "enable_cross_account_access" {
  description = "Enable cross-account access to the bucket"
  type        = bool
  default     = false
}

variable "cross_account_roles" {
  description = "List of cross-account role ARNs for bucket access"
  type        = list(string)
  default     = []
  
  validation {
    condition = !var.enable_cross_account_access || (
      length(var.cross_account_roles) > 0 && alltrue([
        for role in var.cross_account_roles : can(regex("^arn:aws:iam::[0-9]{12}:role/", role))
      ])
    )
    error_message = "Cross-account roles must be provided and be valid IAM role ARNs when cross-account access is enabled."
  }
}

variable "enable_bucket_key" {
  description = "Enable S3 bucket key for encryption performance"
  type        = bool
  default     = true
}

variable "enable_intelligent_tiering" {
  description = "Enable S3 Intelligent Tiering for cost optimization"
  type        = bool
  default     = false
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock for compliance requirements"
  type        = bool
  default     = false
}

variable "object_lock_retention_days" {
  description = "Object lock retention period in days"
  type        = number
  default     = 2555  # 7 years for PII
  
  validation {
    condition     = !var.enable_object_lock || (var.object_lock_retention_days >= 1 && var.object_lock_retention_days <= 36500)
    error_message = "Object lock retention days must be between 1 and 36500 when object lock is enabled."
  }
}

# =============================================================================
# EMERGENCY CONTACT VARIABLES
# =============================================================================

variable "emergency_contact_name" {
  description = "Name of the emergency contact person"
  type        = string
  default     = "Security Team Lead"
  
  validation {
    condition     = length(var.emergency_contact_name) >= 3 && length(var.emergency_contact_name) <= 100
    error_message = "Emergency contact name must be between 3 and 100 characters."
  }
}

variable "emergency_contact_phone" {
  description = "Phone number for emergency contact"
  type        = string
  default     = "+1-555-0123"
  
  validation {
    condition     = can(regex("^\\+[1-9]\\d{1,14}$", var.emergency_contact_phone))
    error_message = "Emergency contact phone must be a valid international phone number."
  }
}

variable "emergency_contact_email" {
  description = "Email address for emergency contact"
  type        = string
  default     = "emergency@chimera-core.com"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.emergency_contact_email))
    error_message = "Emergency contact email must be a valid email address."
  }
}