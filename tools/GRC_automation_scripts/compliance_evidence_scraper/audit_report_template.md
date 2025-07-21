# Cloud Compliance Audit Report

## Executive Summary

**Report Generated:** {{GENERATED_DATE}}  
**AWS Region:** {{AWS_REGION}}  
**Audit Period:** {{AUDIT_PERIOD}}  
**Total Controls Assessed:** {{TOTAL_CONTROLS}}  

### Compliance Overview

| Framework | Total Controls | Compliant | Partially Compliant | Non-Compliant | Error |
|-----------|----------------|-----------|---------------------|---------------|-------|
| SOC 2 | {{SOC2_TOTAL}} | {{SOC2_COMPLIANT}} | {{SOC2_PARTIAL}} | {{SOC2_NON_COMPLIANT}} | {{SOC2_ERROR}} |
| ISO 27001 | {{ISO27001_TOTAL}} | {{ISO27001_COMPLIANT}} | {{ISO27001_PARTIAL}} | {{ISO27001_NON_COMPLIANT}} | {{ISO27001_ERROR}} |
| PCI DSS | {{PCIDSS_TOTAL}} | {{PCIDSS_COMPLIANT}} | {{PCIDSS_PARTIAL}} | {{PCIDSS_NON_COMPLIANT}} | {{PCIDSS_ERROR}} |
| NIST CSF | {{NISTCSF_TOTAL}} | {{NISTCSF_COMPLIANT}} | {{NISTCSF_PARTIAL}} | {{NISTCSF_NON_COMPLIANT}} | {{NISTCSF_ERROR}} |
| AWS Best Practices | {{AWSBP_TOTAL}} | {{AWSBP_COMPLIANT}} | {{AWSBP_PARTIAL}} | {{AWSBP_NON_COMPLIANT}} | {{AWSBP_ERROR}} |

### Risk Assessment Summary

| Risk Level | Count | Percentage |
|------------|-------|------------|
| Critical | {{CRITICAL_COUNT}} | {{CRITICAL_PERCENT}}% |
| High | {{HIGH_COUNT}} | {{HIGH_PERCENT}}% |
| Medium | {{MEDIUM_COUNT}} | {{MEDIUM_PERCENT}}% |
| Low | {{LOW_COUNT}} | {{LOW_PERCENT}}% |

### Key Findings

#### ✅ Compliant Areas
{{COMPLIANT_AREAS}}

#### ⚠️ Areas Requiring Attention
{{ATTENTION_AREAS}}

#### ❌ Critical Issues
{{CRITICAL_ISSUES}}

## Detailed Findings

### SOC 2 Compliance

#### CC6.1 - Logical Access Controls
- **Status:** {{CC6_1_STATUS}}
- **Risk Level:** {{CC6_1_RISK}}
- **Findings:**
{{CC6_1_FINDINGS}}
- **Recommendations:**
{{CC6_1_RECOMMENDATIONS}}

#### CC6.2 - Access Monitoring
- **Status:** {{CC6_2_STATUS}}
- **Risk Level:** {{CC6_2_RISK}}
- **Findings:**
{{CC6_2_FINDINGS}}
- **Recommendations:**
{{CC6_2_RECOMMENDATIONS}}

### ISO 27001 Compliance

#### A.12.4.1 - Event Logging and Monitoring
- **Status:** {{A12_4_1_STATUS}}
- **Risk Level:** {{A12_4_1_RISK}}
- **Findings:**
{{A12_4_1_FINDINGS}}
- **Recommendations:**
{{A12_4_1_RECOMMENDATIONS}}

#### A.13.2.1 - Data Protection in Transit
- **Status:** {{A13_2_1_STATUS}}
- **Risk Level:** {{A13_2_1_RISK}}
- **Findings:**
{{A13_2_1_FINDINGS}}
- **Recommendations:**
{{A13_2_1_RECOMMENDATIONS}}

### PCI DSS Compliance

#### 3.4.1 - Data at Rest Encryption
- **Status:** {{3_4_1_STATUS}}
- **Risk Level:** {{3_4_1_RISK}}
- **Findings:**
{{3_4_1_FINDINGS}}
- **Recommendations:**
{{3_4_1_RECOMMENDATIONS}}

#### 7.1.1 - Access Control by Job Function
- **Status:** {{7_1_1_STATUS}}
- **Risk Level:** {{7_1_1_RISK}}
- **Findings:**
{{7_1_1_FINDINGS}}
- **Recommendations:**
{{7_1_1_RECOMMENDATIONS}}

## Remediation Plan

### Immediate Actions (0-30 days)
{{IMMEDIATE_ACTIONS}}

### Short-term Actions (30-90 days)
{{SHORT_TERM_ACTIONS}}

### Long-term Actions (90+ days)
{{LONG_TERM_ACTIONS}}

## Evidence Collection Details

### Methodology
This audit was conducted using automated evidence collection tools that:
- Perform read-only operations on AWS resources
- Collect configuration data without accessing sensitive information
- Generate standardized compliance assessments
- Provide actionable remediation guidance

### Evidence Sources
- AWS IAM configuration and policies
- S3 bucket security settings
- CloudTrail logging configuration
- RDS database encryption status
- AWS account security settings

### Limitations
- This audit covers AWS cloud infrastructure only
- Evidence is collected at a point in time
- Some controls may require manual verification
- Additional controls may be required for full compliance

## Appendices

### Appendix A: Control Mapping
{{CONTROL_MAPPING}}

### Appendix B: Evidence Details
{{EVIDENCE_DETAILS}}

### Appendix C: Remediation Timeline
{{REMEDIATION_TIMELINE}}

---

**Report Prepared By:** Cloud Compliance Evidence Scraper  
**Report Version:** 1.0  
**Next Review Date:** {{NEXT_REVIEW_DATE}}  

*This report is generated automatically and should be reviewed by qualified security professionals before being used for compliance purposes.*