#!/bin/bash
# Emergency Rollback Script for S3 Public Access Remediation
# Guardian Priority Score: 10.3/10 (Critical)
#
# WARNING: This script removes security controls and should only be used
# in emergency situations where service disruption has occurred.
#
# Usage: ./rollback.sh [BUCKET_NAME]
# Example: ./rollback.sh my-critical-data-prod

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default bucket name if not provided as argument
DEFAULT_BUCKET_NAME="my-critical-data-prod"
BUCKET_NAME="${1:-$DEFAULT_BUCKET_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file for audit trail
LOG_FILE="rollback_$(date +%Y%m%d_%H%M%S).log"

# =============================================================================
# FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $timestamp: $message" | tee -a "$LOG_FILE"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp: $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp: $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $timestamp: $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

show_warning() {
    echo -e "${RED}"
    echo "=================================================================="
    echo "                        ⚠️  WARNING ⚠️"
    echo "=================================================================="
    echo ""
    echo "This script will REMOVE security controls from the S3 bucket:"
    echo "  Bucket: $BUCKET_NAME"
    echo ""
    echo "The following security measures will be REMOVED:"
    echo "  ❌ S3 Block Public Access settings"
    echo "  ❌ Restrictive bucket policy"
    echo "  ❌ Server-side encryption enforcement"
    echo "  ❌ MFA enforcement"
    echo ""
    echo "This will make the bucket potentially vulnerable to:"
    echo "  🔓 Public access to sensitive data"
    echo "  🔓 Unauthorized data exposure"
    echo "  🔓 Compliance violations"
    echo ""
    echo "USE THIS SCRIPT ONLY IF:"
    echo "  ✅ Service disruption has occurred"
    echo "  ✅ Business operations are impacted"
    echo "  ✅ Security team has approved the rollback"
    echo ""
    echo "=================================================================="
    echo -e "${NC}"
    
    read -p "Do you want to continue with the rollback? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        log "INFO" "Rollback cancelled by user"
        exit 0
    fi
    
    echo ""
    log "WARN" "Proceeding with emergency rollback..."
}

check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        log "ERROR" "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity &> /dev/null; then
        log "ERROR" "AWS credentials are not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    # Check if bucket exists
    if ! aws s3api head-bucket --bucket "$BUCKET_NAME" &> /dev/null; then
        log "ERROR" "Bucket '$BUCKET_NAME' does not exist or you don't have access to it."
        exit 1
    fi
    
    log "SUCCESS" "Prerequisites check passed"
}

backup_current_state() {
    log "INFO" "Backing up current state before rollback..."
    
    # Create backup directory
    BACKUP_DIR="rollback_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup current public access block settings
    if aws s3api get-public-access-block --bucket "$BUCKET_NAME" &> /dev/null; then
        aws s3api get-public-access-block --bucket "$BUCKET_NAME" > "$BACKUP_DIR/public_access_block.json"
        log "INFO" "Backed up public access block settings"
    fi
    
    # Backup current bucket policy
    if aws s3api get-bucket-policy --bucket "$BUCKET_NAME" &> /dev/null; then
        aws s3api get-bucket-policy --bucket "$BUCKET_NAME" > "$BACKUP_DIR/bucket_policy.json"
        log "INFO" "Backed up bucket policy"
    fi
    
    # Backup current encryption settings
    if aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" &> /dev/null; then
        aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" > "$BACKUP_DIR/encryption.json"
        log "INFO" "Backed up encryption settings"
    fi
    
    log "SUCCESS" "Current state backed up to $BACKUP_DIR"
}

rollback_public_access_block() {
    log "INFO" "Rolling back public access block settings..."
    
    aws s3api put-public-access-block \
        --bucket "$BUCKET_NAME" \
        --public-access-block-configuration \
        BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
    
    log "SUCCESS" "Public access block settings rolled back"
}

rollback_bucket_policy() {
    log "INFO" "Rolling back bucket policy..."
    
    # Remove the restrictive bucket policy
    if aws s3api get-bucket-policy --bucket "$BUCKET_NAME" &> /dev/null; then
        aws s3api delete-bucket-policy --bucket "$BUCKET_NAME"
        log "SUCCESS" "Bucket policy removed"
    else
        log "INFO" "No bucket policy to remove"
    fi
}

rollback_encryption() {
    log "INFO" "Rolling back encryption settings..."
    
    # Remove server-side encryption configuration
    if aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" &> /dev/null; then
        aws s3api delete-bucket-encryption --bucket "$BUCKET_NAME"
        log "SUCCESS" "Encryption settings removed"
    else
        log "INFO" "No encryption settings to remove"
    fi
}

rollback_versioning() {
    log "INFO" "Rolling back versioning settings..."
    
    # Disable versioning
    aws s3api put-bucket-versioning --bucket "$BUCKET_NAME" --versioning-configuration Status=Suspended
    
    log "SUCCESS" "Versioning suspended"
}

rollback_access_logging() {
    log "INFO" "Rolling back access logging..."
    
    # Remove access logging configuration
    if aws s3api get-bucket-logging --bucket "$BUCKET_NAME" --query 'LoggingEnabled' --output text 2>/dev/null | grep -q "LoggingEnabled"; then
        aws s3api put-bucket-logging --bucket "$BUCKET_NAME" --bucket-logging-status '{}'
        log "SUCCESS" "Access logging removed"
    else
        log "INFO" "No access logging to remove"
    fi
}

verify_rollback() {
    log "INFO" "Verifying rollback..."
    
    # Check public access block
    local public_access_config
    public_access_config=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        local block_public_acls
        local ignore_public_acls
        local block_public_policy
        local restrict_public_buckets
        
        block_public_acls=$(echo "$public_access_config" | jq -r '.BlockPublicAcls // false')
        ignore_public_acls=$(echo "$public_access_config" | jq -r '.IgnorePublicAcls // false')
        block_public_policy=$(echo "$public_access_config" | jq -r '.BlockPublicPolicy // false')
        restrict_public_buckets=$(echo "$public_access_config" | jq -r '.RestrictPublicBuckets // false')
        
        if [ "$block_public_acls" = "false" ] && [ "$ignore_public_acls" = "false" ] && [ "$block_public_policy" = "false" ] && [ "$restrict_public_buckets" = "false" ]; then
            log "SUCCESS" "Public access block settings rolled back successfully"
        else
            log "ERROR" "Public access block settings not fully rolled back"
        fi
    fi
    
    # Check bucket policy
    if ! aws s3api get-bucket-policy --bucket "$BUCKET_NAME" &> /dev/null; then
        log "SUCCESS" "Bucket policy removed successfully"
    else
        log "ERROR" "Bucket policy still exists"
    fi
    
    # Check encryption
    if ! aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" &> /dev/null; then
        log "SUCCESS" "Encryption settings removed successfully"
    else
        log "ERROR" "Encryption settings still exist"
    fi
    
    log "SUCCESS" "Rollback verification completed"
}

generate_rollback_report() {
    log "INFO" "Generating rollback report..."
    
    cat > "rollback_report_$(date +%Y%m%d_%H%M%S).md" << EOF
# Emergency Rollback Report

## Summary
Emergency rollback was performed on S3 bucket: **$BUCKET_NAME**

## Timestamp
$(date)

## Guardian Priority Score
10.3/10 (Critical)

## Security Finding
AWS S3 bucket '$BUCKET_NAME' was publicly accessible and contained PII data

## Rollback Actions Performed

### 1. Public Access Block
- BlockPublicAcls: false
- IgnorePublicAcls: false
- BlockPublicPolicy: false
- RestrictPublicBuckets: false

### 2. Bucket Policy
- Removed restrictive bucket policy
- Public access is now possible

### 3. Server-Side Encryption
- Removed encryption enforcement
- Objects can be uploaded without encryption

### 4. Versioning
- Suspended bucket versioning

### 5. Access Logging
- Removed access logging configuration

## ⚠️ SECURITY WARNING
The bucket is now potentially vulnerable to:
- Public access to sensitive data
- Unauthorized data exposure
- Compliance violations

## Immediate Actions Required
1. **URGENT**: Investigate and resolve the service disruption
2. **URGENT**: Re-apply security controls as soon as possible
3. **URGENT**: Monitor for any unauthorized access attempts
4. **URGENT**: Update incident response procedures

## Rollback Log
$(cat "$LOG_FILE")

## Next Steps
1. Fix the underlying issue that caused service disruption
2. Re-run the emergency containment script: \`./scripts/emergency_containment.sh $BUCKET_NAME\`
3. Re-run the full Terraform remediation
4. Conduct a security assessment
5. Update incident response procedures

## Emergency Contacts
- Security Team: security@chimera-core.com
- Emergency: emergency@chimera-core.com

## Compliance Impact
This rollback may result in:
- PCI DSS violations
- CIS AWS benchmark failures
- CSA CCM control gaps
- NIST CSF framework violations

EOF
    
    log "SUCCESS" "Rollback report generated"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "INFO" "Starting emergency rollback for bucket: $BUCKET_NAME"
    log "INFO" "Guardian Priority Score: 10.3/10 (Critical)"
    
    # Show warning and get confirmation
    show_warning
    
    # Check prerequisites
    check_prerequisites
    
    # Backup current state
    backup_current_state
    
    # Perform rollback steps
    rollback_public_access_block
    rollback_bucket_policy
    rollback_encryption
    rollback_versioning
    rollback_access_logging
    
    # Verify rollback
    verify_rollback
    
    # Generate report
    generate_rollback_report
    
    log "SUCCESS" "Emergency rollback completed"
    log "WARN" "⚠️  SECURITY WARNING: The bucket is now potentially vulnerable!"
    log "INFO" "Next step: Fix the underlying issue and re-apply security controls"
}

# Handle script interruption
trap 'log "ERROR" "Script interrupted by user"; exit 1' INT TERM

# Run main function
main "$@"