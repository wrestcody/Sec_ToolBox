#!/bin/bash

# Emergency Rollback Script for S3 Security Remediation
# Guardian Priority Score: 10.3/10 (Critical)
# 
# WARNING: This script removes security controls and should only be used
# in emergency situations where service disruption has occurred.
#
# Usage: ./rollback.sh <bucket-name> [--force]
# Example: ./rollback.sh my-critical-data-prod --force

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if bucket name is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[ERROR]${NC} Usage: $0 <bucket-name> [--force]"
    echo -e "${RED}[ERROR]${NC} Example: $0 my-critical-data-prod --force"
    exit 1
fi

BUCKET_NAME="$1"
FORCE_FLAG="${2:-}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="rollback_${BUCKET_NAME}_${TIMESTAMP}.log"

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Function to check AWS CLI
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed"
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS CLI is not configured"
        exit 1
    fi
}

# Function to check bucket exists
check_bucket_exists() {
    log "Checking if bucket '$BUCKET_NAME' exists..."
    if ! aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
        error "Bucket '$BUCKET_NAME' does not exist or you don't have access to it"
        exit 1
    fi
    success "Bucket '$BUCKET_NAME' exists and is accessible"
}

# Function to confirm rollback
confirm_rollback() {
    echo
    echo -e "${RED}⚠️  EMERGENCY ROLLBACK WARNING ⚠️${NC}"
    echo
    echo "This script will REMOVE security controls from bucket: $BUCKET_NAME"
    echo
    echo "The following security controls will be removed:"
    echo "  ❌ S3 Block Public Access settings"
    echo "  ❌ Restrictive bucket policy"
    echo "  ❌ Server-side encryption"
    echo "  ❌ Bucket versioning"
    echo "  ❌ Access logging"
    echo "  ❌ Lifecycle policies"
    echo
    echo -e "${RED}⚠️  WARNING: This will make the bucket publicly accessible again!${NC}"
    echo
    
    if [[ "$FORCE_FLAG" != "--force" ]]; then
        echo -e "${YELLOW}To proceed, run: $0 $BUCKET_NAME --force${NC}"
        echo
        read -p "Are you absolutely sure you want to proceed? Type 'YES' to confirm: " confirmation
        
        if [[ "$confirmation" != "YES" ]]; then
            log "Rollback cancelled by user"
            exit 0
        fi
    fi
    
    log "Rollback confirmed - proceeding with security control removal"
}

# Function to backup current state
backup_current_state() {
    log "Creating backup of current security configuration..."
    
    mkdir -p "rollback_backups/${BUCKET_NAME}_${TIMESTAMP}"
    
    # Backup public access block configuration
    aws s3api get-public-access-block --bucket "$BUCKET_NAME" > "rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/public_access_block.json" 2>/dev/null || true
    
    # Backup bucket policy
    aws s3api get-bucket-policy --bucket "$BUCKET_NAME" > "rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/bucket_policy.json" 2>/dev/null || true
    
    # Backup encryption configuration
    aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" > "rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/encryption.json" 2>/dev/null || true
    
    # Backup versioning configuration
    aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" > "rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/versioning.json" 2>/dev/null || true
    
    # Backup logging configuration
    aws s3api get-bucket-logging --bucket "$BUCKET_NAME" > "rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/logging.json" 2>/dev/null || true
    
    # Backup lifecycle configuration
    aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET_NAME" > "rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/lifecycle.json" 2>/dev/null || true
    
    success "Current state backed up to rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/"
}

# Function to remove public access block
remove_public_access_block() {
    log "Removing S3 Block Public Access settings..."
    
    aws s3api put-public-access-block \
        --bucket "$BUCKET_NAME" \
        --public-access-block-configuration \
        BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
    
    success "Public access block settings removed"
}

# Function to remove bucket policy
remove_bucket_policy() {
    log "Removing bucket policy..."
    
    if aws s3api get-bucket-policy --bucket "$BUCKET_NAME" &>/dev/null; then
        aws s3api delete-bucket-policy --bucket "$BUCKET_NAME"
        success "Bucket policy removed"
    else
        warning "No bucket policy found to remove"
    fi
}

# Function to remove encryption
remove_encryption() {
    log "Removing server-side encryption..."
    
    if aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" &>/dev/null; then
        aws s3api delete-bucket-encryption --bucket "$BUCKET_NAME"
        success "Server-side encryption removed"
    else
        warning "No encryption configuration found to remove"
    fi
}

# Function to disable versioning
disable_versioning() {
    log "Disabling bucket versioning..."
    
    local versioning_status
    versioning_status=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --query 'Status' --output text 2>/dev/null || echo "NotEnabled")
    
    if [[ "$versioning_status" == "Enabled" ]]; then
        aws s3api put-bucket-versioning \
            --bucket "$BUCKET_NAME" \
            --versioning-configuration Status=Suspended
        success "Bucket versioning disabled"
    else
        warning "Versioning is not enabled, nothing to disable"
    fi
}

# Function to remove access logging
remove_access_logging() {
    log "Removing access logging..."
    
    if aws s3api get-bucket-logging --bucket "$BUCKET_NAME" --query 'LoggingEnabled' --output text 2>/dev/null | grep -q -v "None"; then
        aws s3api delete-bucket-logging --bucket "$BUCKET_NAME"
        success "Access logging removed"
    else
        warning "No access logging found to remove"
    fi
}

# Function to remove lifecycle policies
remove_lifecycle_policies() {
    log "Removing lifecycle policies..."
    
    if aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET_NAME" &>/dev/null; then
        aws s3api delete-bucket-lifecycle --bucket "$BUCKET_NAME"
        success "Lifecycle policies removed"
    else
        warning "No lifecycle policies found to remove"
    fi
}

# Function to verify rollback
verify_rollback() {
    log "Verifying rollback completion..."
    
    # Check public access block
    local public_access
    public_access=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "{}")
    
    local block_public_acls
    local ignore_public_acls
    local block_public_policy
    local restrict_public_buckets
    
    block_public_acls=$(echo "$public_access" | jq -r '.BlockPublicAcls // false')
    ignore_public_acls=$(echo "$public_access" | jq -r '.IgnorePublicAcls // false')
    block_public_policy=$(echo "$public_access" | jq -r '.BlockPublicPolicy // false')
    restrict_public_buckets=$(echo "$public_access" | jq -r '.RestrictPublicBuckets // false')
    
    if [[ "$block_public_acls" == "false" && "$ignore_public_acls" == "false" && "$block_public_policy" == "false" && "$restrict_public_buckets" == "false" ]]; then
        success "Public access block settings verified as removed"
    else
        warning "Public access block settings may not be fully removed"
    fi
    
    # Check bucket policy
    if ! aws s3api get-bucket-policy --bucket "$BUCKET_NAME" &>/dev/null; then
        success "Bucket policy verified as removed"
    else
        warning "Bucket policy may still exist"
    fi
    
    # Check encryption
    if ! aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" &>/dev/null; then
        success "Encryption verified as removed"
    else
        warning "Encryption may still be enabled"
    fi
    
    # Check versioning
    local versioning_status
    versioning_status=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --query 'Status' --output text 2>/dev/null || echo "NotEnabled")
    
    if [[ "$versioning_status" == "Suspended" || "$versioning_status" == "NotEnabled" ]]; then
        success "Versioning verified as disabled"
    else
        warning "Versioning may still be enabled"
    fi
    
    success "Rollback verification completed"
}

# Function to generate rollback report
generate_rollback_report() {
    log "Generating rollback report..."
    
    cat > "rollback_report_${BUCKET_NAME}_${TIMESTAMP}.md" << EOF
# Emergency Rollback Report
## S3 Bucket: $BUCKET_NAME
## Timestamp: $(date)

### Executive Summary
Emergency rollback has been performed on S3 bucket '$BUCKET_NAME' due to service disruption concerns.

### Guardian Priority Score
**10.3/10 (Critical) - ROLLBACK PERFORMED**

### Security Controls Removed
1. ❌ S3 Block Public Access settings
2. ❌ Restrictive bucket policy
3. ❌ Server-side encryption
4. ❌ Bucket versioning
5. ❌ Access logging
6. ❌ Lifecycle policies

### ⚠️ SECURITY WARNING
**The bucket is now potentially publicly accessible again!**

### Rollback Details
- **Rollback Timestamp**: $(date)
- **Backup Location**: rollback_backups/${BUCKET_NAME}_${TIMESTAMP}/
- **Log File**: $LOG_FILE

### Compliance Impact
- ❌ **PCI DSS**: Non-compliant (controls removed)
- ❌ **CIS AWS**: Non-compliant (controls removed)
- ❌ **CSA CCM**: Non-compliant (controls removed)
- ❌ **NIST CSF**: Non-compliant (controls removed)

### Immediate Actions Required
1. **URGENT**: Investigate and resolve the service disruption issue
2. **URGENT**: Re-apply security controls once issue is resolved
3. **URGENT**: Monitor for unauthorized access attempts
4. **URGENT**: Notify security team of rollback

### Re-application Instructions
Once the service disruption is resolved:

1. Run emergency containment: \`./scripts/emergency_containment.sh $BUCKET_NAME\`
2. Apply full remediation: \`terraform apply\`
3. Verify controls: \`./scripts/verification.sh $BUCKET_NAME\`

### Emergency Contacts
- Primary: security@company.com
- Backup: oncall@company.com
- Escalation: IMMEDIATE

### Rollback Commands Used
\`\`\`bash
# Remove public access block
aws s3api put-public-access-block --bucket $BUCKET_NAME --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false

# Remove bucket policy
aws s3api delete-bucket-policy --bucket $BUCKET_NAME

# Remove encryption
aws s3api delete-bucket-encryption --bucket $BUCKET_NAME

# Disable versioning
aws s3api put-bucket-versioning --bucket $BUCKET_NAME --versioning-configuration Status=Suspended

# Remove logging
aws s3api delete-bucket-logging --bucket $BUCKET_NAME

# Remove lifecycle
aws s3api delete-bucket-lifecycle --bucket $BUCKET_NAME
\`\`\`

---
*Rollback performed on $(date) - URGENT SECURITY ATTENTION REQUIRED*
EOF
    
    success "Rollback report generated: rollback_report_${BUCKET_NAME}_${TIMESTAMP}.md"
}

# Main execution
main() {
    log "Starting emergency rollback for bucket: $BUCKET_NAME"
    
    # Pre-flight checks
    check_aws_cli
    check_bucket_exists
    
    # Confirm rollback
    confirm_rollback
    
    # Create backup
    backup_current_state
    
    # Remove security controls
    remove_public_access_block
    remove_bucket_policy
    remove_encryption
    disable_versioning
    remove_access_logging
    remove_lifecycle_policies
    
    # Verify rollback
    verify_rollback
    
    # Generate report
    generate_rollback_report
    
    log "Emergency rollback completed!"
    
    echo
    echo -e "${RED}🚨 EMERGENCY ROLLBACK COMPLETED 🚨${NC}"
    echo
    echo "Bucket: $BUCKET_NAME"
    echo "Status: SECURITY CONTROLS REMOVED"
    echo "Report: rollback_report_${BUCKET_NAME}_${TIMESTAMP}.md"
    echo "Log: $LOG_FILE"
    echo
    echo -e "${RED}⚠️  CRITICAL: The bucket is now potentially publicly accessible!${NC}"
    echo -e "${RED}⚠️  URGENT: Re-apply security controls immediately after resolving service issues!${NC}"
    echo
}

# Execute main function
main "$@"