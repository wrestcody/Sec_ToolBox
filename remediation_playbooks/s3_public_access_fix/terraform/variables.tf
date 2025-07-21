# S3 Bucket Security Remediation - Variables
# Defines all input variables with validation and secure defaults

variable "bucket_name" {
  description = "Name of the S3 bucket to secure (must be existing bucket)"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.bucket_name))
    error_message = "Bucket name must be valid S3 bucket name format."
  }
}

variable "environment" {
  description = "Environment name (e.g., prod, staging, dev)"
  type        = string
  default     = "prod"
  
  validation {
    condition     = contains(["prod", "staging", "dev", "test"], var.environment)
    error_message = "Environment must be one of: prod, staging, dev, test."
  }
}

variable "authorized_iam_roles" {
  description = "List of IAM role ARNs authorized to access the bucket"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for role in var.authorized_iam_roles : can(regex("^arn:aws:iam::[0-9]{12}:role/", role))
    ])
    error_message = "All authorized IAM roles must be valid ARNs."
  }
}

variable "authorized_iam_users" {
  description = "List of IAM user ARNs authorized to access the bucket"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for user in var.authorized_iam_users : can(regex("^arn:aws:iam::[0-9]{12}:user/", user))
    ])
    error_message = "All authorized IAM users must be valid ARNs."
  }
}

variable "encryption_algorithm" {
  description = "Server-side encryption algorithm to use"
  type        = string
  default     = "AES256"
  
  validation {
    condition     = contains(["AES256", "aws:kms"], var.encryption_algorithm)
    error_message = "Encryption algorithm must be either AES256 or aws:kms."
  }
}

variable "kms_key_id" {
  description = "KMS key ID for encryption (required if using aws:kms)"
  type        = string
  default     = null
  
  validation {
    condition = var.encryption_algorithm != "aws:kms" || (
      var.kms_key_id != null && can(regex("^arn:aws:kms:", var.kms_key_id))
    )
    error_message = "KMS key ID must be provided and be a valid ARN when using aws:kms encryption."
  }
}

variable "data_retention_days" {
  description = "Number of days to retain noncurrent versions"
  type        = number
  default     = 30
  
  validation {
    condition     = var.data_retention_days >= 1 && var.data_retention_days <= 3650
    error_message = "Data retention days must be between 1 and 3650."
  }
}

variable "alert_emails" {
  description = "List of email addresses for security alerts"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for email in var.alert_emails : can(regex("^[^@]+@[^@]+\\.[^@]+$", email))
    ])
    error_message = "All alert emails must be valid email addresses."
  }
}

variable "bucket_owner" {
  description = "Owner/team responsible for the bucket"
  type        = string
  default     = "security-team"
  
  validation {
    condition     = length(var.bucket_owner) >= 3 && length(var.bucket_owner) <= 50
    error_message = "Bucket owner must be between 3 and 50 characters."
  }
}

variable "cost_center" {
  description = "Cost center for billing purposes"
  type        = string
  default     = "security"
  
  validation {
    condition     = length(var.cost_center) >= 2 && length(var.cost_center) <= 20
    error_message = "Cost center must be between 2 and 20 characters."
  }
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "Chimera-Core"
    Purpose     = "S3-Security-Remediation"
    ManagedBy   = "Terraform"
    Compliance  = "PCI-DSS"
    DataType    = "PII"
    Criticality = "Critical"
  }
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring and alerts"
  type        = bool
  default     = true
}

variable "enable_access_logging" {
  description = "Enable S3 access logging"
  type        = bool
  default     = true
}

variable "enable_versioning" {
  description = "Enable S3 versioning"
  type        = bool
  default     = true
}

variable "enable_lifecycle_policies" {
  description = "Enable S3 lifecycle policies"
  type        = bool
  default     = true
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "AWS region must be in valid format (e.g., us-east-1)."
  }
}

variable "force_destroy" {
  description = "Force destroy resources (use with caution)"
  type        = bool
  default     = false
}

variable "emergency_contacts" {
  description = "Emergency contact information for security incidents"
  type = object({
    primary_contact = string
    backup_contact  = string
    escalation_time = number
  })
  default = {
    primary_contact = "security@company.com"
    backup_contact  = "oncall@company.com"
    escalation_time = 30
  }
  
  validation {
    condition = alltrue([
      can(regex("^[^@]+@[^@]+\\.[^@]+$", var.emergency_contacts.primary_contact)),
      can(regex("^[^@]+@[^@]+\\.[^@]+$", var.emergency_contacts.backup_contact)),
      var.emergency_contacts.escalation_time >= 5 && var.emergency_contacts.escalation_time <= 120
    ])
    error_message = "Emergency contacts must have valid email addresses and escalation time between 5-120 minutes."
  }
}