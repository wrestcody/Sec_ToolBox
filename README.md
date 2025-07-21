# Guardians Armory: Unassailable Digital Evidence Integrity

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-first-green.svg)](SECURITY.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

## Mission Statement

Guardians Armory is a comprehensive security tooling framework that implements **The Guardian's Mandate** - a foundational principle for building systems with unassailable digital evidence integrity and unbreakable chain of custody. This framework ensures that all security tools, audit trails, and forensic evidence meet the most stringent compliance and legal requirements.

**"To Create the Next Generation of Protectors"**

## 🛡️ The Guardian's Mandate

The Guardian's Mandate is built on four core principles:

1. **Cryptographic Tamper-Evident Logging & Data**
   - SHA-256+ hashing for all critical events
   - Verifiable timestamps cryptographically bound to data
   - Immutable, append-only data structures

2. **Automated & Granular Chain of Custody**
   - Every interaction automatically logged with full context
   - Robust IAM policies with least privilege principle
   - Session recording for privileged user actions

3. **Verifiable Ledger for Integrity**
   - Blockchain-style verification of critical events
   - Cryptographic chain linking each event to the previous
   - Regular integrity checkpoints for forensic purposes

4. **Forensic Readiness & Auditability by Design**
   - Standardized forensic data export with cryptographic proofs
   - Independent verification tools for integrity validation
   - Compliance alignment with NIST, ISO 27001, SOC 2, and legal standards

## 🏗️ Architecture

### Core Components

- **GuardianLedger**: Immutable, cryptographically-secured audit ledger
- **IAM Anomaly Detector**: Cloud IAM behavioral anomaly detection with Guardian's Mandate integration
- **Cryptographic Proof System**: SHA-256+ hashing with RSA digital signatures
- **Chain of Custody Tracking**: Complete traceability of all evidence
- **Forensic Export System**: Standardized, machine-readable forensic data export
- **GRC MCP Server**: Secure AI integration with bidirectional accessibility

### Evidence Integrity Levels

- **CRITICAL**: Financial data, PII, security events - cryptographic proofs required
- **HIGH**: Configuration changes, access logs - hashing and timestamping
- **MEDIUM**: System events, performance metrics - basic logging
- **LOW**: Informational logs, debug data - informational only

## Featured Projects

### 🔍 [IAM Privilege Escalation Path Finder](tools/cloud_configuration_auditors/aws_iam_privilege_escalation_finder/)
Advanced graph-based analysis of AWS IAM configurations to identify potential privilege escalation paths. Demonstrates deep understanding of cloud IAM complexity and attack vector analysis.

### 🌐 [Cross-Cloud Network Exposure Auditor](tools/cloud_configuration_auditors/cross_cloud_network_auditor/)
Multi-cloud network security assessment tool covering AWS, Azure, and GCP. Identifies internet-facing resources and overly permissive network configurations.

### 📋 [Cloud Compliance Evidence Collector](tools/data_privacy_tools/cloud_compliance_evidence_collector/)
Automated GRC tool that maps compliance framework controls to cloud infrastructure evidence. Streamlines audit preparation and continuous compliance monitoring.

### 🤖 [Secure LLM Interaction Proxy](projects/secure_llm_proxy/)
Production-ready proxy service implementing security and privacy controls for LLM interactions. Addresses prompt injection, PII protection, and response filtering.

### 🛡️ [GRC MCP Server](grc_mcp_server.py)
Production-ready Model Context Protocol (MCP) server for secure AI assistant integrations with comprehensive security features and bidirectional accessibility.

## Technology Stack Demonstrated

**Cloud Platforms**: AWS, Azure, GCP  
**Languages**: Python, Bash, YAML/JSON  
**Security**: IAM, Network Security, Compliance Frameworks, SAST/DAST  
**AI/ML**: LLM Security, Adversarial ML, Privacy-Preserving AI, MCP Integration  
**DevSecOps**: CI/CD Security, Infrastructure as Code, Policy as Code  
**GRC**: NIST, SOC 2, GDPR, CCPA, Risk Assessment Automation  

## Repository Navigation

```
📁 .github/          # GitHub workflows and templates
📁 docs/             # Comprehensive documentation and philosophy
📁 modules/          # Reusable code libraries and utilities
📁 tools/            # Standalone security and compliance tools
📁 concepts/         # Architectural diagrams and policy templates
📁 projects/         # Integrated mini-applications and PoCs
```

### Quick Start Guides
- [Setup Guide](docs/setup_guide.md) - Environment setup for all tools
- [Contribution Guide](docs/contribution_guide.md) - How to contribute securely
- [Personal Philosophy](docs/personal_philosophy.md) - My approach to Security, GRC & AI

### Trend Analysis
- [2025 Cloud Security Trends](docs/trends_analysis/2025_cloud_security_trends.md)
- [2025 AI Privacy & GRC Trends](docs/trends_analysis/2025_ai_privacy_grc_trends.md)

## 🚀 Quick Start

### Prerequisites

```bash
# Install Python 3.8+
python --version

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

#### 1. Guardian's Mandate Framework

```python
from guardians_mandate import GuardianLedger, EvidenceLevel, AuditEventType

# Initialize the Guardian Ledger
ledger = GuardianLedger()

# Record an event with full integrity guarantees
event_id = ledger.record_event(
    event_type=AuditEventType.SECURITY_EVENT.value,
    user_id="user123",
    session_id="session456",
    source_ip="192.168.1.100",
    user_agent="GuardianApp/1.0",
    action="security_check",
    resource="/api/security",
    details={"check_type": "integrity_verification"},
    evidence_level=EvidenceLevel.CRITICAL
)

# Verify integrity
integrity_result = ledger.verify_integrity()
print(f"Integrity verified: {integrity_result['verified']}")

# Export forensic data
export_path = ledger.export_forensic_data("forensic_export.json")
```

#### 2. GRC MCP Server for AI Integration

```bash
# Generate secure configuration
python grc_mcp_server.py generate-config

# Start the MCP server
python grc_mcp_server.py

# Run demo to see AI integration
python mcp_demo.py
```

#### 3. IAM Anomaly Detector with Guardian's Mandate

```bash
# Run with Guardian's Mandate enabled (default)
python tools/guardians_armory/iam_anomaly_detector/iam_anomaly_detector.py \
    --log-file mock_cloudtrail_logs.json

# Run with Guardian's Mandate disabled
python tools/guardians_armory/iam_anomaly_detector/iam_anomaly_detector.py \
    --log-file mock_cloudtrail_logs.json --disable-guardian-mandate

# Export forensic data
python tools/cloud_configuration_auditors/iam_anomaly_detector/iam_anomaly_detector.py \
    --log-file mock_cloudtrail_logs.json --output-format audit
```

#### 4. Run Tests

```bash
# Run comprehensive test suite
python test_guardians_mandate.py
```

## 📋 Features

### Guardian's Mandate Integration

- **Cryptographic Integrity**: All analysis activities cryptographically signed and verified
- **Immutable Audit Trail**: Every event recorded in the Guardian Ledger
- **Chain of Custody**: Complete traceability of evidence from detection to reporting
- **Forensic Export**: Standardized forensic data export with cryptographic proofs
- **Compliance Alignment**: Enhanced compliance reporting for SOC2, ISO27001, NIST, and CIS

### AI Integration & MCP Server

- **Secure AI Access**: API key authentication and session management
- **Natural Language Queries**: AI assistants can ask questions in plain English
- **Rate Limiting**: 60 requests per minute per client with abuse prevention
- **Audit Logging**: Complete trail of all AI interactions
- **Bidirectional Accessibility**: CLI, GUI, API, and MCP interfaces

### IAM Anomaly Detection

- **Behavioral Analysis**: Machine learning-based anomaly detection
- **User Baseline Building**: Historical activity profiling
- **Real-time Detection**: Continuous monitoring of IAM activities
- **Risk Scoring**: Quantitative risk assessment for each anomaly
- **Compliance Mapping**: Direct mapping to compliance frameworks

### Forensic Capabilities

- **Cryptographic Proofs**: SHA-256+ hashing with RSA signatures
- **Timestamp Verification**: Cryptographically bound timestamps
- **Chain Continuity**: Blockchain-style verification of event chains
- **Export Formats**: JSON, CSV, and audit-ready formats
- **Integrity Checkpoints**: Regular verification points for forensic purposes

## 🔧 Installation

### Option 1: Full Installation

```bash
# Clone the repository
git clone <repository-url>
cd guardians-forge

# Install all dependencies
pip install -r requirements.txt

# Verify installation
python test_guardians_mandate.py
```

### Option 2: Minimal Installation

```bash
# Install only core dependencies
pip install cryptography pycryptodome

# Run in legacy mode (Guardian's Mandate disabled)
python tools/cloud_configuration_auditors/iam_anomaly_detector/iam_anomaly_detector.py \
    --log-file mock_cloudtrail_logs.json --disable-guardian-mandate
```

## 📊 Compliance Support

### SOC2 Compliance

- **CC6.1**: Logical and physical access controls
- **CC6.2**: System access controls  
- **CC6.3**: Data access controls
- **CC7.1**: System operation monitoring
- **CC7.2**: System change management
- **CC7.3**: System development and acquisition

### ISO27001 Compliance

- **A.9.2.1**: User registration and de-registration
- **A.9.2.2**: User access provisioning
- **A.9.2.3**: Access rights management
- **A.12.4.1**: Event logging
- **A.12.4.3**: Administrator and operator logs

### NIST Framework

- **AC-2**: Account Management
- **AC-3**: Access Enforcement
- **AC-6**: Least Privilege
- **AU-2**: Audit Events
- **AU-3**: Content of Audit Records
- **AU-6**: Audit Review, Analysis, and Reporting

## 🔍 Usage Examples

### Example 1: Basic Anomaly Detection

```bash
# Analyze CloudTrail logs for anomalies
python tools/cloud_configuration_auditors/iam_anomaly_detector/iam_anomaly_detector.py \
    --log-file cloudtrail_logs.json \
    --baseline-days 30 \
    --detection-days 7
```

**Output:**
```
🔍 Cloud IAM Behavioral Anomaly Detector
==================================================
📁 Loading CloudTrail logs from: cloudtrail_logs.json
   Loaded 1,247 log entries

⏰ Time Windows:
   Baseline period: 2024-01-01 00:00:00 to 2024-01-31 00:00:00
   Detection period: 2024-01-31 00:00:00 to 2024-02-07 00:00:00

📊 Baseline Analysis:
   1,100 log entries in baseline period
   Building baselines for 15 users...

🔍 Anomaly Detection:
   147 log entries in detection period
   Analyzing user behavior patterns...

🚨 3 Anomaly(ies) Detected:

1. 🔴 new_location_ip
   Time: 2024-02-05T14:30:00Z
   User: admin_user
   Event: ConsoleLogin
   Source IP: 203.0.113.45
   AWS Region: us-east-1
   Risk Score: 6
   Compliance: SOC2:CC6.1, ISO27001:A.9.2.1, NIST:AC-2

🛡️  Guardian's Mandate: Digital Evidence Integrity
==================================================
🔍 Verifying cryptographic integrity...
✅ Integrity verification: PASSED
   Verified blocks: 25/25
   Chain hashes: 25
   Timestamp range: 2024-02-05T14:25:00Z to 2024-02-05T14:35:00Z

📋 Exporting forensic data...
✅ Forensic data exported to: guardian_forensic_abc123.json

🔗 Chain of Custody Report:
   1. User: admin_user - Type: new_location_ip
      Evidence recorded in Guardian Ledger with cryptographic proof

🛡️  Guardian's Mandate Summary:
   Session ID: abc123-def456-ghi789
   Evidence Integrity: CRITICAL
   Chain of Custody: VERIFIED
   Forensic Export: guardian_forensic_abc123.json
   Compliance Ready: YES
```

### Example 2: AI Integration with MCP Server

```bash
# Start MCP server for AI assistant integration
python grc_mcp_server.py

# AI Assistant can now ask:
# "What's our current compliance status?"
# "Show me all SOC2 controls"
# "Run assessment on access control CC6.1"
```

### Example 3: Forensic Export

```bash
# Export forensic data for compliance
python tools/cloud_configuration_auditors/iam_anomaly_detector/iam_anomaly_detector.py \
    --log-file cloudtrail_logs.json \
    --output-format audit \
    --output-file compliance_report.json
```

**Output:**
```
📋 Exporting forensic data...
✅ Forensic data exported to: guardian_forensic_abc123.json

📊 Compliance Report Generated:
   - SOC2 Controls: 6/6 compliant
   - ISO27001 Controls: 5/5 compliant  
   - NIST Controls: 6/6 compliant
   - Overall Risk Level: MEDIUM
   - Evidence Integrity: VERIFIED
   - Chain of Custody: COMPLETE
```

### Example 4: Custom Guardian's Mandate Integration

```python
from guardians_mandate import GuardianLedger, EvidenceLevel, AuditEventType

# Initialize custom ledger
ledger = GuardianLedger(
    ledger_path="custom_audit_ledger",
    enable_blockchain_verification=True
)

# Record security events
security_event_id = ledger.record_event(
    event_type=AuditEventType.SECURITY_EVENT.value,
    user_id="security_analyst",
    session_id="session_789",
    source_ip="10.0.0.100",
    user_agent="SecurityTool/2.0",
    action="threat_detection",
    resource="/security/threats",
    details={
        "threat_type": "malware",
        "severity": "high",
        "affected_systems": ["web-server-01", "db-server-02"]
    },
    evidence_level=EvidenceLevel.CRITICAL
)

# Verify chain of custody
chain = ledger.get_chain_of_custody(security_event_id)
print(f"Chain of custody: {len(chain)} events")

# Export for forensic analysis
export_path = ledger.export_forensic_data("security_forensic.json")
print(f"Forensic data: {export_path}")
```

## 🔒 Security Considerations

### Key Management

- Master keys are auto-generated using cryptographically secure random number generation
- Private keys are generated using RSA-2048 with proper padding
- Keys should be stored securely in production environments

### Data Protection

- All sensitive data is hashed and cryptographically signed
- Nonces are used to prevent replay attacks
- Timestamps are cryptographically bound to prevent tampering

### Audit Trail Protection

- Audit trails are immutable and append-only
- Each event is cryptographically linked to the previous event
- Integrity checkpoints are created regularly for forensic purposes

### AI Integration Security

- API key authentication with secure key management
- Rate limiting to prevent abuse
- Complete audit trail of all AI interactions
- Input validation and sanitization

## 🧪 Testing

### Run All Tests

```bash
python test_guardians_mandate.py
```

### Test Individual Components

```bash
# Test Guardian's Mandate framework only
python -c "
from test_guardians_mandate import test_guardian_mandate_framework
test_guardian_mandate_framework()
"

# Test IAM Anomaly Detector integration
python -c "
from test_guardians_mandate import test_iam_anomaly_detector_integration
test_iam_anomaly_detector_integration()
"

# Test MCP Server
python mcp_demo.py
```

## 📚 Documentation

- **[The Guardian's Mandate Framework](GUARDIANS_MANDATE.md)**: Comprehensive documentation of the core framework
- **[IAM Anomaly Detector Documentation](tools/cloud_configuration_auditors/iam_anomaly_detector/README.md)**: Detailed usage guide for the anomaly detector
- **[Compliance Guidelines](tools/cloud_configuration_auditors/iam_anomaly_detector/AUDIT_READINESS.md)**: Compliance and audit readiness documentation
- **[MCP Server Documentation](MCP_SERVER_README.md)**: AI integration guide and security best practices

## 🤝 Contributing

### Development Setup

```bash
# Clone and setup development environment
git clone <repository-url>
cd guardians-forge

# Install development dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install

# Run tests
python test_guardians_mandate.py
```

### Code Standards

- Follow PEP 8 style guidelines
- Include comprehensive docstrings
- Write unit tests for all new features
- Ensure Guardian's Mandate compliance for all security-related code

## Professional Background & Expertise

With extensive experience in Security, Privacy, Compliance, and AI, particularly in AWS SaaS environments, I've built and operated cloud solutions at scale. This repository demonstrates practical applications of:

- **Cloud Security Architecture**: Zero-trust implementations, IAM optimization, network security
- **GRC Automation**: Compliance-as-code, risk assessment automation, audit preparation
- **AI Security**: LLM safety, adversarial ML defense, privacy-preserving AI techniques
- **DevSecOps**: Security integration throughout the development lifecycle
- **Digital Evidence Integrity**: Unassailable chain of custody and forensic readiness

## Connect & Collaborate

🔗 **LinkedIn**: [Your LinkedIn Profile]  
🌐 **Website**: [Your Professional Website]  
📧 **Email**: [your.professional.email@domain.com]  
🐙 **GitHub**: You're already here!  

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Common Issues

1. **Import Error**: Guardian's Mandate framework not available
   ```bash
   pip install -r requirements.txt
   ```

2. **Integrity Verification Failed**
   - Check for file corruption or unauthorized modifications
   - Verify that the ledger files haven't been tampered with

3. **Performance Issues**
   - Consider using database backends for large-scale deployments
   - Implement batch processing for high-volume events

4. **MCP Server Issues**
   - Install MCP library: `pip install mcp`
   - Generate secure configuration: `python grc_mcp_server.py generate-config`
   - Check audit logs for security events

### Getting Help

- Check the [documentation](GUARDIANS_MANDATE.md)
- Run the test suite: `python test_guardians_mandate.py`
- Review the [troubleshooting guide](GUARDIANS_MANDATE.md#troubleshooting)

## 🔮 Roadmap

### Planned Features

1. **Distributed Ledger**: Integration with blockchain networks for decentralized verification
2. **Trusted Timestamping**: RFC 3161 compliant timestamping authority integration
3. **Advanced Cryptography**: Post-quantum cryptography support
4. **Cloud Integration**: Native integration with AWS, Azure, and GCP services
5. **Real-time Monitoring**: Real-time integrity monitoring and alerting
6. **Additional Security Tools**: Integration with more security tools and frameworks
7. **Enhanced AI Integration**: Advanced natural language processing and AI assistant capabilities

### Version History

- **v2.1.0**: GRC MCP Server with AI integration and bidirectional accessibility
- **v2.0.0**: Guardian's Mandate integration with IAM Anomaly Detector
- **v1.0.0**: Initial IAM Anomaly Detector release

---

**The Guardian's Forge** - Building security tools with unassailable digital evidence integrity and unbreakable chain of custody.

*"Security is not a product, but a process. This repository is my contribution to that ongoing process."*
