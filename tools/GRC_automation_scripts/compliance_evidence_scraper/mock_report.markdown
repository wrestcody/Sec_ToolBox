# Cloud Compliance Evidence Report (Mock Data)

**Generated:** 2025-07-20 23:52:50 UTC
**AWS Region:** us-east-1
**Controls Checked:** 3
**Note:** This is mock data for demonstration purposes

## Summary

### Frameworks Covered

- **SOC 2:** 2 controls
- **ISO 27001:** 1 controls

### Evidence Types Collected

- **iam:** 2 controls
- **cloudtrail:** 1 controls

### Compliance Status Summary

- ⚠️ **Partially Compliant:** 3 controls

### Risk Level Distribution

- 🟠 **High:** 2 controls
- 🟡 **Medium:** 1 controls

## Detailed Evidence

### CC6.1 - Logical access is restricted to authorized users

**Framework:** SOC 2
**Category:** CC - Control Activities
**Type:** iam
**Risk Level:** 🟠 High
**Compliance Status:** ⚠️ Partially Compliant
**Timestamp:** 2025-07-20T23:52:50.411836+00:00

**Findings:**
- ✅ Root account MFA is enabled
- ✅ Minimum password length is 12+ characters
- ✅ Password policy requires symbols
- ✅ Password policy requires numbers
- ✅ Password policy requires uppercase characters
- ✅ Password policy requires lowercase characters
- ✅ Password policy requires password expiration
- ✅ Password expiration is set to 90 days
- ⚠️ 3 users have AdministratorAccess policy

**Recommendations:**
- Review and reduce the number of administrative users

**Data Summary:**
- **root_mfa_enabled:** True
- **root_mfa_status:** Enabled
- **password_policy:** 7 items
- **admin_users_count:** 3
- **admin_users:** 3 items

---

### CC6.2 - Access to systems and data is restricted to authorized personnel

**Framework:** SOC 2
**Category:** CC - Control Activities
**Type:** iam
**Risk Level:** 🟡 Medium
**Compliance Status:** ⚠️ Partially Compliant
**Timestamp:** 2025-07-20T23:52:50.411870+00:00

**Findings:**
- ✅ Root account MFA is enabled
- ✅ Minimum password length is 12+ characters
- ✅ Password policy requires symbols
- ✅ Password policy requires numbers
- ✅ Password policy requires uppercase characters
- ✅ Password policy requires lowercase characters
- ✅ Password policy requires password expiration
- ✅ Password expiration is set to 90 days
- ⚠️ 3 users have AdministratorAccess policy

**Recommendations:**
- Review and reduce the number of administrative users

**Data Summary:**
- **root_mfa_enabled:** True
- **root_mfa_status:** Enabled
- **password_policy:** 7 items
- **admin_users_count:** 3
- **admin_users:** 3 items

---

### A.12.4.1 - Event logging and monitoring

**Framework:** ISO 27001
**Category:** A.12 - Operations Security
**Type:** cloudtrail
**Risk Level:** 🟠 High
**Compliance Status:** ⚠️ Partially Compliant
**Timestamp:** 2025-07-20T23:52:50.411878+00:00

**Findings:**
- ✅ 2 CloudTrail trail(s) configured
- ✅ 1 multi-region trail(s) configured
- ⚠️ 1 trail(s) have log file validation enabled
- ✅ All 2 CloudTrail trail(s) are actively logging

**Recommendations:**
- Enable log file validation for CloudTrail trails

**Data Summary:**
- **total_trails:** 2
- **multi_region_trails:** 1
- **trails:** 2 items
- **logging_status:** 2 items

---
