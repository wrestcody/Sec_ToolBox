# Cloud IAM Behavioral Anomaly Detector

A Python CLI tool that analyzes AWS CloudTrail logs for unusual IAM activity patterns that could indicate a compromised identity or privilege escalation. This tool is specifically designed for **audit evidence and compliance reporting purposes**.

## 🎯 Purpose

Identity and Access Management (IAM) is a critical security component in AWS environments. Compromised IAM credentials can lead to unauthorized access, data breaches, and privilege escalation attacks. This tool helps security teams and auditors identify suspicious IAM activity patterns that may indicate:

- **Credential compromise**: Unusual login locations or times
- **Privilege escalation**: Unexpected policy changes or role assumptions
- **Account takeover**: First-time access from new locations
- **Malicious activity**: Overly permissive policy creation

## 🔍 How It Works

The tool uses a **baseline-based anomaly detection** approach with comprehensive audit capabilities:

1. **Baseline Building**: Analyzes historical CloudTrail logs to establish normal behavior patterns for each user
2. **Anomaly Detection**: Compares recent activity against established baselines to identify deviations
3. **Risk Assessment**: Categorizes anomalies by severity and provides actionable recommendations
4. **Compliance Mapping**: Maps findings to major compliance frameworks (SOC2, ISO27001, NIST, CIS)
5. **Audit Reporting**: Generates structured reports suitable for compliance audits

### Detection Capabilities

| Anomaly Type | Description | Severity | Risk Score | Compliance Impact |
|--------------|-------------|----------|------------|-------------------|
| **New Location/IP** | User accesses from previously unseen IP address or AWS region | Medium | 6 | SOC2:CC6.1, ISO27001:A.9.2.1, NIST:AC-2 |
| **Unusual Policy Changes** | User makes policy modifications when they rarely do so | High | 8 | SOC2:CC6.3, ISO27001:A.9.2.3, NIST:AC-6 |
| **Overly Permissive Policies** | Creation of policies with wildcard (`*`) permissions | Critical | 10 | SOC2:CC6.3, ISO27001:A.9.2.3, NIST:AC-6, CIS:1.3 |
| **First-Time Role Assumption** | User assumes a role they've never used before | Medium | 7 | SOC2:CC6.2, ISO27001:A.9.2.2, NIST:AC-3 |
| **Unusual Event Types** | User performs actions outside their normal activity pattern | Low | 3 | SOC2:CC6.1, ISO27001:A.9.2.1, NIST:AC-2 |

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- No external dependencies required (uses only Python standard library)

### Installation

1. Clone or download the tool files
2. Ensure the script is executable:
   ```bash
   chmod +x iam_anomaly_detector.py
   ```

### Basic Usage

```bash
# Analyze mock CloudTrail logs with default settings (console output)
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json

# Generate JSON report for further analysis
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json --output-format json --output-file report.json

# Generate comprehensive audit report
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json --output-format audit --output-file audit_report.json

# Export findings to CSV for spreadsheet analysis
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json --output-format csv --output-file findings.csv

# Customize baseline and detection periods
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json --baseline-days 60 --detection-days 7 --output-format audit --output-file audit_report.json
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--log-file` | Path to CloudTrail log JSON file | Required |
| `--baseline-days` | Days of historical data for baseline | 30 |
| `--detection-days` | Days of recent data to analyze | 1 |
| `--output-format` | Output format (console, json, csv, audit) | console |
| `--output-file` | Output file path (required for non-console formats) | - |
| `--version` | Show version information | - |

## 📊 Output Formats

### 1. Console Output (Default)
Human-readable output with emojis and formatted text:

```
🔍 Cloud IAM Behavioral Anomaly Detector
==================================================
📁 Loading CloudTrail logs from: mock_cloudtrail_logs.json
   Loaded 15 log entries

⏰ Time Windows:
   Baseline period: 2024-01-01 00:00:00 to 2024-01-15 00:00:00
   Detection period: 2024-01-15 00:00:00 to 2024-01-16 00:00:00

🚨 3 Anomaly(ies) Detected:

================================================================================
1. 🚨 Overly Permissive Policy
   Time: 2024-01-21T11:45:00Z
   User: john.doe
   Event: PutUserPolicy
   Source IP: 203.0.113.45
   AWS Region: eu-west-1
   Risk Score: 10
   Compliance: SOC2:CC6.3, ISO27001:A.9.2.3, NIST:AC-6, CIS:1.3
   Description: User 'john.doe' created/attached policy with wildcard permissions (*)
   Recommendation: Immediately review and restrict overly permissive policy
--------------------------------------------------------------------------------
```

### 2. JSON Output
Structured JSON format for programmatic analysis:

```json
{
  "anomalies": [
    {
      "event_time": "2024-01-21T11:45:00Z",
      "username": "john.doe",
      "event_name": "PutUserPolicy",
      "source_ip": "203.0.113.45",
      "aws_region": "eu-west-1",
      "anomaly_type": "overly_permissive_policy",
      "severity": "critical",
      "description": "User 'john.doe' created/attached policy with wildcard permissions (*)",
      "recommendation": "Immediately review and restrict overly permissive policy",
      "compliance_impact": ["SOC2:CC6.3", "ISO27001:A.9.2.3", "NIST:AC-6", "CIS:1.3"],
      "risk_score": 10,
      "evidence": {
        "policy_document": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
        "wildcard_detected": true,
        "user_privilege_level": "medium"
      }
    }
  ],
  "metadata": {
    "baseline_days": 30,
    "detection_days": 1,
    "total_logs_processed": 15
  }
}
```

### 3. CSV Output
Spreadsheet-friendly format for data analysis:

```csv
event_time,username,event_name,source_ip,aws_region,anomaly_type,severity,description,recommendation,risk_score,compliance_impact
2024-01-21T11:45:00Z,john.doe,PutUserPolicy,203.0.113.45,eu-west-1,overly_permissive_policy,critical,"User 'john.doe' created/attached policy with wildcard permissions (*)","Immediately review and restrict overly permissive policy",10,"SOC2:CC6.3; ISO27001:A.9.2.3; NIST:AC-6; CIS:1.3"
```

### 4. Audit Report (JSON)
Comprehensive audit report suitable for compliance purposes:

```json
{
  "audit_metadata": {
    "report_generated": "2024-01-25T10:30:00Z",
    "tool_version": "1.0.0",
    "analysis_parameters": {
      "baseline_days": 30,
      "detection_days": 1,
      "total_logs_processed": 15
    },
    "compliance_frameworks": {
      "SOC2": ["CC6.1", "CC6.2", "CC6.3"],
      "ISO27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
      "NIST": ["AC-2", "AC-3", "AC-6"],
      "CIS": ["1.1", "1.2", "1.3"]
    }
  },
  "executive_summary": {
    "total_anomalies": 3,
    "critical_anomalies": 1,
    "high_anomalies": 0,
    "medium_anomalies": 2,
    "low_anomalies": 0,
    "total_users_analyzed": 4,
    "overall_risk_level": "CRITICAL"
  },
  "compliance_assessment": {
    "soc2": {
      "CC6.1": {"status": "NON_COMPLIANT", "findings": [...]},
      "CC6.2": {"status": "NON_COMPLIANT", "findings": [...]},
      "CC6.3": {"status": "NON_COMPLIANT", "findings": [...]}
    },
    "iso27001": {
      "A.9.2.1": {"status": "NON_COMPLIANT", "findings": [...]},
      "A.9.2.2": {"status": "NON_COMPLIANT", "findings": [...]},
      "A.9.2.3": {"status": "NON_COMPLIANT", "findings": [...]}
    }
  },
  "recommendations": [
    {
      "priority": "HIGH",
      "category": "Overly Permissive Policy",
      "description": "Address 1 overly_permissive_policy anomaly(ies)",
      "action_items": ["Immediately review and restrict overly permissive policy"],
      "affected_users": ["john.doe"],
      "risk_score": 10
    }
  ],
  "risk_assessment": {
    "overall_risk": "CRITICAL",
    "average_risk_score": 7.0,
    "total_risk_score": 21,
    "risk_factors": [...]
  }
}
```

## 🔧 Configuration

### Time Windows

- **Baseline Period**: Historical data used to establish normal behavior patterns
- **Detection Period**: Recent data analyzed for anomalies

### Risk Scoring

The tool uses a 1-10 risk scoring system:

- **1-3**: Low risk (informational)
- **4-6**: Medium risk (requires attention)
- **7-8**: High risk (immediate action recommended)
- **9-10**: Critical risk (urgent action required)

### Compliance Frameworks

The tool maps findings to major compliance frameworks:

- **SOC2**: CC6.1, CC6.2, CC6.3 (Logical and Physical Access Controls)
- **ISO27001**: A.9.2.1, A.9.2.2, A.9.2.3 (User Access Management)
- **NIST**: AC-2, AC-3, AC-6 (Access Control)
- **CIS**: 1.1, 1.2, 1.3 (Identity and Access Management)

## 🛡️ Security Considerations

### Important Limitations

⚠️ **This is a proof-of-concept tool with significant limitations:**

1. **Mock Data Only**: Uses simulated CloudTrail logs, not real AWS data
2. **Basic Detection**: Uses simple statistical methods, not advanced ML
3. **No Real-time Monitoring**: Analyzes static log files, not live streams
4. **Limited Scope**: Focuses on IAM events only

### Production Considerations

For production use, consider:

- **Real-time Integration**: Connect to AWS CloudTrail via API
- **Advanced ML Models**: Implement machine learning for better accuracy
- **Alert Integration**: Connect to SIEM/SOAR platforms
- **False Positive Reduction**: Implement whitelisting and tuning
- **Compliance**: Ensure logging and monitoring meet regulatory requirements

## 📁 File Structure

```
iam_anomaly_detector/
├── iam_anomaly_detector.py      # Main CLI tool with audit capabilities
├── mock_cloudtrail_logs.json    # Sample CloudTrail data with anomalies
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## 🔄 CloudTrail Log Format

The tool expects CloudTrail logs in JSON format with the following structure:

```json
[
  {
    "eventTime": "2024-01-15T10:30:00Z",
    "eventName": "ConsoleLogin",
    "userIdentity": {
      "userName": "john.doe",
      "type": "IAMUser",
      "arn": "arn:aws:iam::123456789012:user/john.doe"
    },
    "eventSource": "signin.amazonaws.com",
    "sourceIPAddress": "192.168.1.100",
    "awsRegion": "us-east-1"
  }
]
```

## 📋 Audit Evidence Features

### For Compliance Audits

1. **Structured Evidence**: All findings include detailed evidence and context
2. **Compliance Mapping**: Direct mapping to major compliance frameworks
3. **Risk Assessment**: Quantified risk scores and overall risk levels
4. **Recommendations**: Prioritized action items for remediation
5. **Audit Trail**: Complete metadata about analysis parameters and timing
6. **Multiple Formats**: Export capabilities for different audit needs

### For Security Teams

1. **Actionable Intelligence**: Specific recommendations for each finding
2. **Risk Prioritization**: Findings sorted by severity and risk score
3. **User Context**: Historical activity patterns for each user
4. **Evidence Collection**: Detailed evidence supporting each anomaly
5. **Trend Analysis**: Baseline vs. detection period comparisons

## 🚀 Future Enhancements

### Planned Features

- **Real AWS Integration**: Direct CloudTrail API access
- **Machine Learning**: Advanced anomaly detection algorithms
- **Visualization**: Charts and graphs for activity patterns
- **Alerting**: Email/Slack notifications for critical anomalies
- **Configuration**: YAML-based rule configuration
- **HTML Reports**: Web-based report generation
- **PDF Reports**: Printable audit reports
- **API Interface**: REST API for integration with other tools

### Contributing

This tool is part of the Cloud Sentinel's Toolkit. Contributions are welcome!

## 📄 License

This tool is provided as-is for educational and research purposes. Use in production environments at your own risk.

## ⚠️ Disclaimer

This tool is designed for security research and educational purposes. Always:

- Test thoroughly in non-production environments
- Review and validate all detected anomalies
- Follow your organization's security policies
- Never rely solely on automated tools for security decisions
- Ensure compliance with applicable data protection regulations

---

**Remember**: Security is a shared responsibility. This tool is just one component of a comprehensive security strategy.