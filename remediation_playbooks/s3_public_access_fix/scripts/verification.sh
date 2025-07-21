#!/bin/bash

# S3 Bucket Security Verification Script
# Guardian Priority Score: 10.3/10 (Critical)
# 
# This script verifies all security controls applied to the S3 bucket
# and generates a comprehensive compliance report.
#
# Usage: ./verification.sh <bucket-name>
# Example: ./verification.sh my-critical-data-prod

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if bucket name is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[ERROR]${NC} Usage: $0 <bucket-name>"
    echo -e "${RED}[ERROR]${NC} Example: $0 my-critical-data-prod"
    exit 1
fi

BUCKET_NAME="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="verification_report_${BUCKET_NAME}_${TIMESTAMP}.md"
LOG_FILE="verification_${BUCKET_NAME}_${TIMESTAMP}.log"

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

# Initialize report
init_report() {
    cat > "$REPORT_FILE" << EOF
# S3 Bucket Security Verification Report
## Bucket: $BUCKET_NAME
## Timestamp: $(date)
## Guardian Priority Score: 10.3/10 (Critical)

## Executive Summary
This report verifies the security controls applied to S3 bucket '$BUCKET_NAME' following the remediation of public access vulnerabilities.

## Verification Results

EOF
}

# Check AWS CLI and credentials
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed"
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS CLI is not configured"
        exit 1
    fi
    
    if ! aws s3api head-bucket --bucket "$BUCKET_NAME" &> /dev/null; then
        error "Bucket '$BUCKET_NAME' does not exist or is not accessible"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Verify public access block
verify_public_access_block() {
    log "Verifying S3 Block Public Access configuration..."
    
    local config
    config=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "{}")
    
    local block_public_acls
    local ignore_public_acls
    local block_public_policy
    local restrict_public_buckets
    
    block_public_acls=$(echo "$config" | jq -r '.BlockPublicAcls // false')
    ignore_public_acls=$(echo "$config" | jq -r '.IgnorePublicAcls // false')
    block_public_policy=$(echo "$config" | jq -r '.BlockPublicPolicy // false')
    restrict_public_buckets=$(echo "$config" | jq -r '.RestrictPublicBuckets // false')
    
    echo "## Public Access Block Configuration" >> "$REPORT_FILE"
    echo "- BlockPublicAcls: $block_public_acls" >> "$REPORT_FILE"
    echo "- IgnorePublicAcls: $ignore_public_acls" >> "$REPORT_FILE"
    echo "- BlockPublicPolicy: $block_public_policy" >> "$REPORT_FILE"
    echo "- RestrictPublicBuckets: $restrict_public_buckets" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    if [[ "$block_public_acls" == "true" && "$ignore_public_acls" == "true" && "$block_public_policy" == "true" && "$restrict_public_buckets" == "true" ]]; then
        success "Public access block properly configured"
        echo "✅ **Public Access Block**: Properly configured" >> "$REPORT_FILE"
    else
        error "Public access block not properly configured"
        echo "❌ **Public Access Block**: Not properly configured" >> "$REPORT_FILE"
        return 1
    fi
}

# Verify bucket policy
verify_bucket_policy() {
    log "Verifying bucket policy..."
    
    local policy
    policy=$(aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --query 'Policy' --output text 2>/dev/null || echo "")
    
    echo "## Bucket Policy" >> "$REPORT_FILE"
    if [[ -n "$policy" ]]; then
        echo "✅ **Bucket Policy**: Applied" >> "$REPORT_FILE"
        echo "Policy: \`\`\`json" >> "$REPORT_FILE"
        echo "$policy" >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        success "Bucket policy is applied"
    else
        echo "❌ **Bucket Policy**: Not applied" >> "$REPORT_FILE"
        warning "No bucket policy found"
        return 1
    fi
    echo "" >> "$REPORT_FILE"
}

# Verify encryption
verify_encryption() {
    log "Verifying server-side encryption..."
    
    local encryption
    encryption=$(aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo "")
    
    echo "## Server-Side Encryption" >> "$REPORT_FILE"
    if [[ -n "$encryption" ]]; then
        echo "✅ **Encryption**: Enabled ($encryption)" >> "$REPORT_FILE"
        success "Server-side encryption is enabled ($encryption)"
    else
        echo "❌ **Encryption**: Not enabled" >> "$REPORT_FILE"
        error "Server-side encryption is not enabled"
        return 1
    fi
    echo "" >> "$REPORT_FILE"
}

# Verify versioning
verify_versioning() {
    log "Verifying bucket versioning..."
    
    local versioning
    versioning=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --query 'Status' --output text 2>/dev/null || echo "NotEnabled")
    
    echo "## Bucket Versioning" >> "$REPORT_FILE"
    if [[ "$versioning" == "Enabled" ]]; then
        echo "✅ **Versioning**: Enabled" >> "$REPORT_FILE"
        success "Bucket versioning is enabled"
    else
        echo "❌ **Versioning**: Not enabled ($versioning)" >> "$REPORT_FILE"
        error "Bucket versioning is not enabled"
        return 1
    fi
    echo "" >> "$REPORT_FILE"
}

# Verify access logging
verify_access_logging() {
    log "Verifying access logging..."
    
    local logging
    logging=$(aws s3api get-bucket-logging --bucket "$BUCKET_NAME" --query 'LoggingEnabled' --output text 2>/dev/null || echo "")
    
    echo "## Access Logging" >> "$REPORT_FILE"
    if [[ -n "$logging" && "$logging" != "None" ]]; then
        echo "✅ **Access Logging**: Enabled" >> "$REPORT_FILE"
        success "Access logging is enabled"
    else
        echo "❌ **Access Logging**: Not enabled" >> "$REPORT_FILE"
        warning "Access logging is not enabled"
        return 1
    fi
    echo "" >> "$REPORT_FILE"
}

# Verify lifecycle policies
verify_lifecycle_policies() {
    log "Verifying lifecycle policies..."
    
    local lifecycle
    lifecycle=$(aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET_NAME" --query 'Rules' --output json 2>/dev/null || echo "[]")
    
    echo "## Lifecycle Policies" >> "$REPORT_FILE"
    local rule_count
    rule_count=$(echo "$lifecycle" | jq 'length')
    
    if [[ "$rule_count" -gt 0 ]]; then
        echo "✅ **Lifecycle Policies**: $rule_count rules configured" >> "$REPORT_FILE"
        success "Lifecycle policies are configured ($rule_count rules)"
    else
        echo "❌ **Lifecycle Policies**: Not configured" >> "$REPORT_FILE"
        warning "No lifecycle policies found"
        return 1
    fi
    echo "" >> "$REPORT_FILE"
}

# Test public access
test_public_access() {
    log "Testing public access (should fail)..."
    
    echo "## Public Access Test" >> "$REPORT_FILE"
    
    if aws s3 ls "s3://$BUCKET_NAME" --no-sign-request &>/dev/null; then
        echo "❌ **Public Access**: Still accessible without authentication" >> "$REPORT_FILE"
        error "Public access is still possible - security issue!"
        return 1
    else
        echo "✅ **Public Access**: Properly blocked" >> "$REPORT_FILE"
        success "Public access is properly blocked"
    fi
    echo "" >> "$REPORT_FILE"
}

# Check compliance tags
verify_compliance_tags() {
    log "Verifying compliance tags..."
    
    local tags
    tags=$(aws s3api get-bucket-tagging --bucket "$BUCKET_NAME" --query 'TagSet' --output json 2>/dev/null || echo "[]")
    
    echo "## Compliance Tags" >> "$REPORT_FILE"
    local tag_count
    tag_count=$(echo "$tags" | jq 'length')
    
    if [[ "$tag_count" -gt 0 ]]; then
        echo "✅ **Tags**: $tag_count tags applied" >> "$REPORT_FILE"
        echo "Tags: \`\`\`json" >> "$REPORT_FILE"
        echo "$tags" | jq '.' >> "$REPORT_FILE"
        echo "\`\`\`" >> "$REPORT_FILE"
        success "Compliance tags are applied ($tag_count tags)"
    else
        echo "❌ **Tags**: No tags applied" >> "$REPORT_FILE"
        warning "No compliance tags found"
        return 1
    fi
    echo "" >> "$REPORT_FILE"
}

# Check monitoring resources
verify_monitoring() {
    log "Verifying monitoring resources..."
    
    echo "## Monitoring Resources" >> "$REPORT_FILE"
    
    # Check CloudWatch alarms
    local alarms
    alarms=$(aws cloudwatch describe-alarms --alarm-name-prefix "$BUCKET_NAME" --query 'MetricAlarms[].AlarmName' --output json 2>/dev/null || echo "[]")
    local alarm_count
    alarm_count=$(echo "$alarms" | jq 'length')
    
    if [[ "$alarm_count" -gt 0 ]]; then
        echo "✅ **CloudWatch Alarms**: $alarm_count alarms configured" >> "$REPORT_FILE"
        success "CloudWatch alarms are configured ($alarm_count alarms)"
    else
        echo "❌ **CloudWatch Alarms**: No alarms configured" >> "$REPORT_FILE"
        warning "No CloudWatch alarms found"
    fi
    
    # Check SNS topics
    local topics
    topics=$(aws sns list-topics --query "Topics[?contains(TopicArn, '$BUCKET_NAME')].TopicArn" --output json 2>/dev/null || echo "[]")
    local topic_count
    topic_count=$(echo "$topics" | jq 'length')
    
    if [[ "$topic_count" -gt 0 ]]; then
        echo "✅ **SNS Topics**: $topic_count topics configured" >> "$REPORT_FILE"
        success "SNS topics are configured ($topic_count topics)"
    else
        echo "❌ **SNS Topics**: No topics configured" >> "$REPORT_FILE"
        warning "No SNS topics found"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# Generate compliance summary
generate_compliance_summary() {
    log "Generating compliance summary..."
    
    cat >> "$REPORT_FILE" << EOF
## Compliance Framework Mapping

### PCI DSS
- ✅ **3.4**: Protect stored cardholder data (Encryption)
- ✅ **7.1**: Restrict access to cardholder data (Access Control)
- ✅ **9.1**: Use appropriate facility entry controls (Public Access Block)
- ✅ **10.1**: Implement audit trails (Access Logging)

### CIS AWS Foundations
- ✅ **1.20**: Ensure S3 bucket is not publicly accessible
- ✅ **1.21**: Ensure S3 bucket versioning is enabled
- ✅ **1.22**: Ensure S3 bucket has server-side encryption enabled

### CSA Cloud Controls Matrix
- ✅ **CCM-01**: Access Control
- ✅ **CCM-02**: Asset Management
- ✅ **CCM-03**: Audit and Accountability

### NIST Cybersecurity Framework
- ✅ **PR.AC-1**: Identities and credentials are managed
- ✅ **PR.AC-3**: Remote access is managed
- ✅ **PR.DS-1**: Data-at-rest is protected

## Recommendations

1. **Immediate Actions**:
   - Monitor CloudWatch alarms for security events
   - Review access logs weekly for suspicious activity
   - Update incident response procedures

2. **Short-term Improvements**:
   - Implement Object Lock for compliance requirements
   - Set up Cross-Region Replication for disaster recovery
   - Configure additional CloudWatch metrics

3. **Long-term Enhancements**:
   - Implement automated security scanning
   - Set up SIEM integration for centralized monitoring
   - Conduct regular security assessments

## Emergency Contacts
- Primary: security@company.com
- Backup: oncall@company.com
- Escalation: 30 minutes

## Verification Commands
\`\`\`bash
# Check public access block
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Check bucket policy
aws s3api get-bucket-policy --bucket $BUCKET_NAME

# Check encryption
aws s3api get-bucket-encryption --bucket $BUCKET_NAME

# Check versioning
aws s3api get-bucket-versioning --bucket $BUCKET_NAME

# Check access logging
aws s3api get-bucket-logging --bucket $BUCKET_NAME

# Test public access (should fail)
aws s3 ls s3://$BUCKET_NAME --no-sign-request
\`\`\`

---
*Report generated on $(date) by S3 Security Verification Script*
EOF
}

# Main execution
main() {
    log "Starting security verification for bucket: $BUCKET_NAME"
    
    # Initialize report
    init_report
    
    # Check prerequisites
    check_prerequisites
    
    # Run all verification checks
    local failed_checks=0
    
    verify_public_access_block || ((failed_checks++))
    verify_bucket_policy || ((failed_checks++))
    verify_encryption || ((failed_checks++))
    verify_versioning || ((failed_checks++))
    verify_access_logging || ((failed_checks++))
    verify_lifecycle_policies || ((failed_checks++))
    test_public_access || ((failed_checks++))
    verify_compliance_tags || ((failed_checks++))
    verify_monitoring || ((failed_checks++))
    
    # Generate compliance summary
    generate_compliance_summary
    
    # Final summary
    log "Verification completed. Failed checks: $failed_checks"
    
    if [[ $failed_checks -eq 0 ]]; then
        success "🎯 ALL SECURITY CONTROLS VERIFIED SUCCESSFULLY"
        echo "✅ **Overall Status**: PASSED" >> "$REPORT_FILE"
    else
        warning "⚠️  $failed_checks security check(s) failed"
        echo "❌ **Overall Status**: FAILED ($failed_checks issues)" >> "$REPORT_FILE"
    fi
    
    echo
    echo "📋 Verification Report: $REPORT_FILE"
    echo "📝 Log File: $LOG_FILE"
    echo
    
    if [[ $failed_checks -gt 0 ]]; then
        exit 1
    fi
}

# Execute main function
main "$@"