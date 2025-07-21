#!/bin/bash
# Verification Script for S3 Public Access Remediation
# Guardian Priority Score: 10.3/10 (Critical)
#
# This script verifies that all security controls have been properly applied
# after the S3 public access remediation
#
# Usage: ./verification.sh [BUCKET_NAME]
# Example: ./verification.sh my-critical-data-prod

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
LOG_FILE="verification_$(date +%Y%m%d_%H%M%S).log"

# Verification results
VERIFICATION_RESULTS=()
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

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

record_result() {
    local check_name="$1"
    local status="$2"
    local details="$3"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ "$status" = "PASS" ]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        log "SUCCESS" "✓ $check_name: PASS"
    else
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        log "ERROR" "✗ $check_name: FAIL - $details"
    fi
    
    VERIFICATION_RESULTS+=("$check_name|$status|$details")
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

verify_public_access_block() {
    log "INFO" "Verifying S3 Block Public Access settings..."
    
    local public_access_config
    public_access_config=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        record_result "Public Access Block" "FAIL" "Could not retrieve public access block configuration"
        return
    fi
    
    # Check each setting
    local block_public_acls
    local ignore_public_acls
    local block_public_policy
    local restrict_public_buckets
    
    block_public_acls=$(echo "$public_access_config" | jq -r '.BlockPublicAcls // false')
    ignore_public_acls=$(echo "$public_access_config" | jq -r '.IgnorePublicAcls // false')
    block_public_policy=$(echo "$public_access_config" | jq -r '.BlockPublicPolicy // false')
    restrict_public_buckets=$(echo "$public_access_config" | jq -r '.RestrictPublicBuckets // false')
    
    if [ "$block_public_acls" = "true" ] && [ "$ignore_public_acls" = "true" ] && [ "$block_public_policy" = "true" ] && [ "$restrict_public_buckets" = "true" ]; then
        record_result "Public Access Block" "PASS" "All public access settings are properly configured"
    else
        record_result "Public Access Block" "FAIL" "BlockPublicAcls=$block_public_acls, IgnorePublicAcls=$ignore_public_acls, BlockPublicPolicy=$block_public_policy, RestrictPublicBuckets=$restrict_public_buckets"
    fi
}

verify_bucket_policy() {
    log "INFO" "Verifying bucket policy..."
    
    local bucket_policy
    bucket_policy=$(aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --query 'Policy' --output text 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        record_result "Bucket Policy" "FAIL" "Could not retrieve bucket policy"
        return
    fi
    
    # Check if policy contains deny statements for public access
    if echo "$bucket_policy" | grep -q '"Effect": "Deny"' && echo "$bucket_policy" | grep -q '"Principal": "*"'; then
        record_result "Bucket Policy" "PASS" "Bucket policy contains appropriate deny statements for public access"
    else
        record_result "Bucket Policy" "FAIL" "Bucket policy does not contain appropriate deny statements for public access"
    fi
}

verify_encryption() {
    log "INFO" "Verifying server-side encryption..."
    
    local encryption_config
    encryption_config=$(aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" --query 'ServerSideEncryptionConfiguration' --output json 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        record_result "Server-Side Encryption" "FAIL" "Could not retrieve encryption configuration"
        return
    fi
    
    local sse_algorithm
    local bucket_key_enabled
    
    sse_algorithm=$(echo "$encryption_config" | jq -r '.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // "none"')
    bucket_key_enabled=$(echo "$encryption_config" | jq -r '.Rules[0].BucketKeyEnabled // false')
    
    if [ "$sse_algorithm" = "AES256" ] || [ "$sse_algorithm" = "aws:kms" ]; then
        record_result "Server-Side Encryption" "PASS" "Encryption enabled with algorithm: $sse_algorithm, BucketKey: $bucket_key_enabled"
    else
        record_result "Server-Side Encryption" "FAIL" "Encryption not properly configured. Algorithm: $sse_algorithm"
    fi
}

verify_versioning() {
    log "INFO" "Verifying bucket versioning..."
    
    local versioning_status
    versioning_status=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --query 'Status' --output text 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        record_result "Bucket Versioning" "FAIL" "Could not retrieve versioning status"
        return
    fi
    
    if [ "$versioning_status" = "Enabled" ]; then
        record_result "Bucket Versioning" "PASS" "Bucket versioning is enabled"
    else
        record_result "Bucket Versioning" "FAIL" "Bucket versioning is not enabled. Status: $versioning_status"
    fi
}

verify_access_logging() {
    log "INFO" "Verifying access logging..."
    
    local logging_config
    logging_config=$(aws s3api get-bucket-logging --bucket "$BUCKET_NAME" --output json 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        record_result "Access Logging" "FAIL" "Could not retrieve logging configuration"
        return
    fi
    
    local target_bucket
    target_bucket=$(echo "$logging_config" | jq -r '.LoggingEnabled.TargetBucket // "none"')
    
    if [ "$target_bucket" != "none" ]; then
        record_result "Access Logging" "PASS" "Access logging enabled with target bucket: $target_bucket"
    else
        record_result "Access Logging" "FAIL" "Access logging is not configured"
    fi
}

verify_public_access_test() {
    log "INFO" "Testing public access (should fail)..."
    
    # Test public access without authentication
    if aws s3 ls "s3://$BUCKET_NAME" --no-sign-request &> /dev/null; then
        record_result "Public Access Test" "FAIL" "Public access is still possible - this is a security risk!"
    else
        record_result "Public Access Test" "PASS" "Public access is properly blocked"
    fi
}

verify_authorized_access() {
    log "INFO" "Testing authorized access..."
    
    # Test access with proper authentication
    if aws s3 ls "s3://$BUCKET_NAME" &> /dev/null; then
        record_result "Authorized Access" "PASS" "Authorized access works correctly"
    else
        record_result "Authorized Access" "FAIL" "Authorized access is not working - check IAM permissions"
    fi
}

verify_monitoring_resources() {
    log "INFO" "Verifying monitoring resources..."
    
    # Check if CloudWatch log group exists
    local log_group_name="/aws/s3/$BUCKET_NAME/access"
    if aws logs describe-log-groups --log-group-name-prefix "$log_group_name" --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$log_group_name"; then
        record_result "CloudWatch Log Group" "PASS" "CloudWatch log group exists: $log_group_name"
    else
        record_result "CloudWatch Log Group" "FAIL" "CloudWatch log group not found: $log_group_name"
    fi
    
    # Check if SNS topic exists
    local sns_topic_name="chimera-core-security-alerts"
    if aws sns list-topics --query "Topics[?contains(TopicArn, '$sns_topic_name')].TopicArn" --output text 2>/dev/null | grep -q "$sns_topic_name"; then
        record_result "SNS Topic" "PASS" "SNS topic exists: $sns_topic_name"
    else
        record_result "SNS Topic" "FAIL" "SNS topic not found: $sns_topic_name"
    fi
}

verify_compliance_tags() {
    log "INFO" "Verifying compliance tags..."
    
    local bucket_tags
    bucket_tags=$(aws s3api get-bucket-tagging --bucket "$BUCKET_NAME" --output json 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        record_result "Compliance Tags" "FAIL" "Could not retrieve bucket tags"
        return
    fi
    
    # Check for required tags
    local has_compliance_tag=false
    local has_data_type_tag=false
    local has_criticality_tag=false
    
    if echo "$bucket_tags" | jq -r '.TagSet[] | select(.Key=="Compliance") | .Value' | grep -q "PCI-DSS\|CIS-AWS\|CSA-CCM"; then
        has_compliance_tag=true
    fi
    
    if echo "$bucket_tags" | jq -r '.TagSet[] | select(.Key=="DataType") | .Value' | grep -q "PII"; then
        has_data_type_tag=true
    fi
    
    if echo "$bucket_tags" | jq -r '.TagSet[] | select(.Key=="Criticality") | .Value' | grep -q "Critical"; then
        has_criticality_tag=true
    fi
    
    if [ "$has_compliance_tag" = "true" ] && [ "$has_data_type_tag" = "true" ] && [ "$has_criticality_tag" = "true" ]; then
        record_result "Compliance Tags" "PASS" "All required compliance tags are present"
    else
        record_result "Compliance Tags" "FAIL" "Missing required tags. Compliance: $has_compliance_tag, DataType: $has_data_type_tag, Criticality: $has_criticality_tag"
    fi
}

generate_verification_report() {
    log "INFO" "Generating verification report..."
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local report_file="verification_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# S3 Security Remediation Verification Report

## Summary
Verification of security controls for S3 bucket: **$BUCKET_NAME**

## Timestamp
$timestamp

## Guardian Priority Score
10.3/10 (Critical)

## Verification Results

### Overall Status
- **Total Checks**: $TOTAL_CHECKS
- **Passed**: $PASSED_CHECKS
- **Failed**: $FAILED_CHECKS
- **Success Rate**: $((PASSED_CHECKS * 100 / TOTAL_CHECKS))%

### Detailed Results

EOF
    
    for result in "${VERIFICATION_RESULTS[@]}"; do
        IFS='|' read -r check_name status details <<< "$result"
        if [ "$status" = "PASS" ]; then
            echo "- ✅ **$check_name**: PASS" >> "$report_file"
        else
            echo "- ❌ **$check_name**: FAIL - $details" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << EOF

## Compliance Frameworks Addressed
- PCI DSS 3.4, 7.1, 9.1
- CIS AWS 1.20, 1.21, 1.22
- CSA CCM CCM-01, CCM-02, CCM-03
- NIST CSF PR.AC-1, PR.AC-3, PR.DS-1

## Security Controls Verified
1. S3 Block Public Access
2. Secure Bucket Policy
3. Server-Side Encryption
4. Bucket Versioning
5. Access Logging
6. Public Access Testing
7. Authorized Access Testing
8. Monitoring Resources
9. Compliance Tags

## Recommendations

EOF
    
    if [ $FAILED_CHECKS -eq 0 ]; then
        echo "- ✅ All security controls are properly configured" >> "$report_file"
        echo "- ✅ The bucket is secure and compliant" >> "$report_file"
        echo "- ✅ Continue with regular monitoring and maintenance" >> "$report_file"
    else
        echo "- ⚠️ Some security controls failed verification" >> "$report_file"
        echo "- 🔧 Review and fix failed controls" >> "$report_file"
        echo "- 🔍 Re-run verification after fixes" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

## Next Steps
1. Address any failed verifications
2. Implement regular security monitoring
3. Update incident response procedures
4. Schedule periodic security reviews

## Emergency Contacts
- Security Team: security@chimera-core.com
- Emergency: emergency@chimera-core.com

EOF
    
    log "SUCCESS" "Verification report generated: $report_file"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    log "INFO" "Starting verification for bucket: $BUCKET_NAME"
    log "INFO" "Guardian Priority Score: 10.3/10 (Critical)"
    
    # Check prerequisites
    check_prerequisites
    
    # Run all verification checks
    verify_public_access_block
    verify_bucket_policy
    verify_encryption
    verify_versioning
    verify_access_logging
    verify_public_access_test
    verify_authorized_access
    verify_monitoring_resources
    verify_compliance_tags
    
    # Generate report
    generate_verification_report
    
    # Summary
    log "INFO" "Verification completed"
    log "INFO" "Total checks: $TOTAL_CHECKS, Passed: $PASSED_CHECKS, Failed: $FAILED_CHECKS"
    
    if [ $FAILED_CHECKS -eq 0 ]; then
        log "SUCCESS" "All security controls verified successfully!"
        exit 0
    else
        log "ERROR" "$FAILED_CHECKS checks failed. Please review and fix the issues."
        exit 1
    fi
}

# Handle script interruption
trap 'log "ERROR" "Script interrupted by user"; exit 1' INT TERM

# Run main function
main "$@"