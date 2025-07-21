#!/bin/bash
# Emergency Containment Script for S3 Public Access Remediation
# Guardian Priority Score: 10.3/10 (Critical)
#
# This script provides immediate containment for the critical security finding:
# AWS S3 bucket 'my-critical-data-prod' is publicly accessible and contains PII data
#
# Usage: ./emergency_containment.sh [BUCKET_NAME]
# Example: ./emergency_containment.sh my-critical-data-prod

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
LOG_FILE="emergency_containment_$(date +%Y%m%d_%H%M%S).log"

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
    log "INFO" "Backing up current bucket state..."
    
    # Create backup directory
    BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
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
    
    # Backup current versioning settings
    if aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" &> /dev/null; then
        aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" > "$BACKUP_DIR/versioning.json"
        log "INFO" "Backed up versioning settings"
    fi
    
    log "SUCCESS" "Current state backed up to $BACKUP_DIR"
}

check_current_public_access() {
    log "INFO" "Checking current public access status..."
    
    # Check if bucket is publicly accessible
    if aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json | grep -q '"BlockPublicAcls": false'; then
        log "WARN" "Bucket has public ACLs enabled - this is a security risk!"
        return 1
    fi
    
    if aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json | grep -q '"BlockPublicPolicy": false'; then
        log "WARN" "Bucket allows public policies - this is a security risk!"
        return 1
    fi
    
    if aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json | grep -q '"RestrictPublicBuckets": false'; then
        log "WARN" "Bucket is not restricted from public access - this is a security risk!"
        return 1
    fi
    
    log "SUCCESS" "Bucket public access is properly restricted"
    return 0
}

apply_emergency_containment() {
    log "INFO" "Applying emergency containment measures..."
    
    # Step 1: Block all public access
    log "INFO" "Step 1: Blocking all public access to bucket..."
    aws s3api put-public-access-block \
        --bucket "$BUCKET_NAME" \
        --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    
    log "SUCCESS" "Public access blocked"
    
    # Step 2: Apply restrictive bucket policy
    log "INFO" "Step 2: Applying restrictive bucket policy..."
    
    cat > /tmp/emergency_policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyPublicReadAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:GetObjectAcl",
                "s3:GetObjectVersionAcl"
            ],
            "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
        },
        {
            "Sid": "EnforceEncryption",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::$BUCKET_NAME/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "AES256"
                }
            }
        }
    ]
}
EOF
    
    aws s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy file:///tmp/emergency_policy.json
    rm -f /tmp/emergency_policy.json
    
    log "SUCCESS" "Restrictive bucket policy applied"
    
    # Step 3: Enable server-side encryption
    log "INFO" "Step 3: Enabling server-side encryption..."
    
    cat > /tmp/encryption_config.json << EOF
{
    "Rules": [
        {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            },
            "BucketKeyEnabled": true
        }
    ]
}
EOF
    
    aws s3api put-bucket-encryption --bucket "$BUCKET_NAME" --server-side-encryption-configuration file:///tmp/encryption_config.json
    rm -f /tmp/encryption_config.json
    
    log "SUCCESS" "Server-side encryption enabled"
    
    # Step 4: Enable versioning
    log "INFO" "Step 4: Enabling bucket versioning..."
    aws s3api put-bucket-versioning --bucket "$BUCKET_NAME" --versioning-configuration Status=Enabled
    
    log "SUCCESS" "Bucket versioning enabled"
}

verify_containment() {
    log "INFO" "Verifying containment measures..."
    
    # Verify public access block
    log "INFO" "Verifying public access block..."
    if aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json | grep -q '"BlockPublicAcls": true'; then
        log "SUCCESS" "Public ACLs are blocked"
    else
        log "ERROR" "Public ACLs are not blocked"
        return 1
    fi
    
    # Verify bucket policy
    log "INFO" "Verifying bucket policy..."
    if aws s3api get-bucket-policy --bucket "$BUCKET_NAME" &> /dev/null; then
        log "SUCCESS" "Bucket policy is applied"
    else
        log "ERROR" "Bucket policy is not applied"
        return 1
    fi
    
    # Verify encryption
    log "INFO" "Verifying encryption..."
    if aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" &> /dev/null; then
        log "SUCCESS" "Server-side encryption is enabled"
    else
        log "ERROR" "Server-side encryption is not enabled"
        return 1
    fi
    
    # Verify versioning
    log "INFO" "Verifying versioning..."
    if aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --query 'Status' --output text | grep -q "Enabled"; then
        log "SUCCESS" "Bucket versioning is enabled"
    else
        log "ERROR" "Bucket versioning is not enabled"
        return 1
    fi
    
    # Test public access (should fail)
    log "INFO" "Testing public access (should fail)..."
    if aws s3 ls "s3://$BUCKET_NAME" --no-sign-request &> /dev/null; then
        log "ERROR" "Public access is still possible - containment failed!"
        return 1
    else
        log "SUCCESS" "Public access is properly blocked"
    fi
    
    log "SUCCESS" "All containment measures verified successfully"
}

generate_report() {
    log "INFO" "Generating emergency containment report..."
    
    cat > "emergency_containment_report_$(date +%Y%m%d_%H%M%S).md" << EOF
# Emergency Containment Report

## Summary
Emergency containment measures were applied to S3 bucket: **$BUCKET_NAME**

## Timestamp
$(date)

## Guardian Priority Score
10.3/10 (Critical)

## Security Finding
AWS S3 bucket '$BUCKET_NAME' was publicly accessible and contained PII data

## Containment Measures Applied

### 1. Public Access Block
- BlockPublicAcls: true
- IgnorePublicAcls: true
- BlockPublicPolicy: true
- RestrictPublicBuckets: true

### 2. Restrictive Bucket Policy
- Denied public read access to all objects
- Enforced server-side encryption for uploads
- Applied least privilege principle

### 3. Server-Side Encryption
- Algorithm: AES256
- Bucket Key: Enabled

### 4. Versioning
- Status: Enabled

## Verification Results
$(grep "SUCCESS\|ERROR" "$LOG_FILE" | tail -10)

## Next Steps
1. Review and update authorized roles/users in production.tfvars
2. Run full Terraform remediation for comprehensive security controls
3. Implement monitoring and alerting
4. Update incident response procedures

## Emergency Contacts
- Security Team: security@chimera-core.com
- Emergency: emergency@chimera-core.com

## Rollback Instructions
If service disruption occurs, run:
\`\`\`bash
./scripts/rollback.sh $BUCKET_NAME
\`\`\`

EOF
    
    log "SUCCESS" "Emergency containment report generated"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "INFO" "Starting emergency containment for bucket: $BUCKET_NAME"
    log "INFO" "Guardian Priority Score: 10.3/10 (Critical)"
    
    # Check prerequisites
    check_prerequisites
    
    # Backup current state
    backup_current_state
    
    # Check current public access status
    if check_current_public_access; then
        log "WARN" "Bucket appears to already have proper security controls"
        log "INFO" "Proceeding with additional security hardening..."
    fi
    
    # Apply emergency containment
    apply_emergency_containment
    
    # Verify containment
    if verify_containment; then
        log "SUCCESS" "Emergency containment completed successfully"
    else
        log "ERROR" "Emergency containment verification failed"
        exit 1
    fi
    
    # Generate report
    generate_report
    
    log "SUCCESS" "Emergency containment process completed"
    log "INFO" "Next step: Run full Terraform remediation for comprehensive security controls"
}

# Handle script interruption
trap 'log "ERROR" "Script interrupted by user"; exit 1' INT TERM

# Run main function
main "$@"