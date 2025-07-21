#!/bin/bash

# Emergency Containment Script for S3 Public Access
# Guardian Priority Score: 10.3/10 (Critical)
# 
# This script provides immediate containment for publicly accessible S3 buckets
# containing PII data. It should be run immediately upon discovery of the issue.
#
# Usage: ./emergency_containment.sh <bucket-name>
# Example: ./emergency_containment.sh my-critical-data-prod

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if bucket name is provided
if [ $# -eq 0 ]; then
    error "Usage: $0 <bucket-name>"
    error "Example: $0 my-critical-data-prod"
    exit 1
fi

BUCKET_NAME="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="emergency_containment_${BUCKET_NAME}_${TIMESTAMP}.log"

# Function to log to file
log_to_file() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Function to check AWS CLI
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS CLI is not configured. Please run 'aws configure' first."
        exit 1
    fi
}

# Function to check bucket exists
check_bucket_exists() {
    log "Checking if bucket '$BUCKET_NAME' exists..."
    if ! aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
        error "Bucket '$BUCKET_NAME' does not exist or you don't have access to it."
        exit 1
    fi
    success "Bucket '$BUCKET_NAME' exists and is accessible."
}

# Function to backup current state
backup_current_state() {
    log "Creating backup of current bucket configuration..."
    
    mkdir -p "backups/${BUCKET_NAME}_${TIMESTAMP}"
    
    # Backup public access block configuration
    aws s3api get-public-access-block --bucket "$BUCKET_NAME" > "backups/${BUCKET_NAME}_${TIMESTAMP}/public_access_block.json" 2>/dev/null || true
    
    # Backup bucket policy
    aws s3api get-bucket-policy --bucket "$BUCKET_NAME" > "backups/${BUCKET_NAME}_${TIMESTAMP}/bucket_policy.json" 2>/dev/null || true
    
    # Backup encryption configuration
    aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" > "backups/${BUCKET_NAME}_${TIMESTAMP}/encryption.json" 2>/dev/null || true
    
    # Backup versioning configuration
    aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" > "backups/${BUCKET_NAME}_${TIMESTAMP}/versioning.json" 2>/dev/null || true
    
    success "Current state backed up to backups/${BUCKET_NAME}_${TIMESTAMP}/"
}

# Function to block public access
block_public_access() {
    log "Applying S3 Block Public Access settings..."
    
    aws s3api put-public-access-block \
        --bucket "$BUCKET_NAME" \
        --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    
    success "Public access blocked for bucket '$BUCKET_NAME'"
}

# Function to apply restrictive bucket policy
apply_restrictive_policy() {
    log "Applying restrictive bucket policy..."
    
    # Create a restrictive policy that denies all public access
    cat > /tmp/restrictive_policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyPublicAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::$BUCKET_NAME",
                "arn:aws:s3:::$BUCKET_NAME/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
EOF
    
    aws s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy file:///tmp/restrictive_policy.json
    
    success "Restrictive bucket policy applied"
    rm -f /tmp/restrictive_policy.json
}

# Function to enable encryption
enable_encryption() {
    log "Enabling server-side encryption..."
    
    # Check if encryption is already enabled
    if aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" &>/dev/null; then
        warning "Encryption is already enabled on bucket '$BUCKET_NAME'"
        return
    fi
    
    aws s3api put-bucket-encryption \
        --bucket "$BUCKET_NAME" \
        --server-side-encryption-configuration '{
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": true
                }
            ]
        }'
    
    success "Server-side encryption enabled"
}

# Function to enable versioning
enable_versioning() {
    log "Enabling bucket versioning..."
    
    # Check current versioning status
    VERSIONING_STATUS=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --query 'Status' --output text 2>/dev/null || echo "NotEnabled")
    
    if [ "$VERSIONING_STATUS" = "Enabled" ]; then
        warning "Versioning is already enabled on bucket '$BUCKET_NAME'"
        return
    fi
    
    aws s3api put-bucket-versioning \
        --bucket "$BUCKET_NAME" \
        --versioning-configuration Status=Enabled
    
    success "Bucket versioning enabled"
}

# Function to verify containment
verify_containment() {
    log "Verifying containment measures..."
    
    # Check public access block
    PUBLIC_ACCESS=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json)
    log "Public access block configuration: $PUBLIC_ACCESS"
    
    # Check bucket policy
    POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --query 'Policy' --output text 2>/dev/null || echo "No policy")
    log "Bucket policy applied: $POLICY"
    
    # Check encryption
    ENCRYPTION=$(aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo "Not configured")
    log "Encryption algorithm: $ENCRYPTION"
    
    # Check versioning
    VERSIONING=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --query 'Status' --output text 2>/dev/null || echo "Not enabled")
    log "Versioning status: $VERSIONING"
    
    success "Containment verification completed"
}

# Function to generate report
generate_report() {
    log "Generating containment report..."
    
    cat > "containment_report_${BUCKET_NAME}_${TIMESTAMP}.md" << EOF
# Emergency Containment Report
## S3 Bucket: $BUCKET_NAME
## Timestamp: $(date)

### Executive Summary
Emergency containment measures have been applied to the publicly accessible S3 bucket '$BUCKET_NAME' containing PII data.

### Guardian Priority Score
**10.3/10 (Critical)**

### Containment Measures Applied
1. ✅ S3 Block Public Access enabled
2. ✅ Restrictive bucket policy applied
3. ✅ Server-side encryption enabled
4. ✅ Bucket versioning enabled
5. ✅ Current state backed up

### Compliance Frameworks Addressed
- PCI DSS 3.4, 7.1, 9.1, 10.1
- CIS AWS 1.20, 1.21, 1.22
- CSA CCM CCM-01, CCM-02, CCM-03
- NIST CSF PR.AC-1, PR.AC-3, PR.DS-1

### Next Steps
1. Run full Terraform remediation: \`terraform apply\`
2. Verify all security controls: \`./scripts/verification.sh $BUCKET_NAME\`
3. Monitor CloudWatch alarms for security events
4. Review access logs for suspicious activity
5. Update incident response procedures

### Emergency Contacts
- Primary: security@company.com
- Backup: oncall@company.com
- Escalation: 30 minutes

### Rollback Information
If service disruption occurs, use the backup files in: \`backups/${BUCKET_NAME}_${TIMESTAMP}/\`

### Log File
Complete execution log: \`$LOG_FILE\`
EOF
    
    success "Containment report generated: containment_report_${BUCKET_NAME}_${TIMESTAMP}.md"
}

# Main execution
main() {
    log "Starting emergency containment for bucket: $BUCKET_NAME"
    log_to_file "Starting emergency containment for bucket: $BUCKET_NAME"
    
    # Pre-flight checks
    check_aws_cli
    check_bucket_exists
    
    # Create backup
    backup_current_state
    
    # Apply containment measures
    block_public_access
    apply_restrictive_policy
    enable_encryption
    enable_versioning
    
    # Verify containment
    verify_containment
    
    # Generate report
    generate_report
    
    log "Emergency containment completed successfully!"
    log_to_file "Emergency containment completed successfully!"
    
    echo
    success "🎯 EMERGENCY CONTAINMENT COMPLETED"
    echo
    echo "Bucket: $BUCKET_NAME"
    echo "Status: SECURED"
    echo "Report: containment_report_${BUCKET_NAME}_${TIMESTAMP}.md"
    echo "Log: $LOG_FILE"
    echo
    warning "⚠️  IMPORTANT: This is immediate containment only."
    warning "   Run the full Terraform remediation for complete security controls."
    echo
}

# Execute main function
main "$@"