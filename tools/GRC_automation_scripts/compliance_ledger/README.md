# Compliance Ledger: Policy-as-Code & Verifiable Evidence Collector
## with AWS Config Integration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![AWS Config](https://img.shields.io/badge/AWS-Config-orange.svg)](https://aws.amazon.com/config/)

> **The Guardian's Forge: Cloud Security, GRC & AI Solutions**

A robust, open-source Python CLI tool that automates the collection, validation, and secure storage of GRC (Governance, Risk, and Compliance) evidence from AWS environments. This tool intelligently leverages **AWS Config** as a key integration point for scalable, continuous compliance monitoring, in addition to direct API calls.

## 🛡️ The Guardian's Mandate

Compliance Ledger implements **The Guardian's Mandate** - ensuring unassailable digital evidence integrity and an unbreakable chain of custody for all collected data. Every piece of evidence is cryptographically secured with SHA-256 hashing, trusted timestamps, and immutable storage concepts.

### Core Principles

- **🔐 Cryptographic Integrity**: Every evidence bundle includes a SHA-256 hash computed immediately upon collection
- **⏰ Trusted Timestamps**: UTC timestamps recorded at the moment of evidence collection
- **🔗 Chain of Custody**: Complete audit trail from collection to storage
- **🛡️ Immutable Storage**: Evidence bundles designed for WORM (Write Once Read Many) storage
- **📊 Policy-as-Code**: Compliance controls defined in human-readable YAML

## 🎯 The Problem This Tool Solves

Manual GRC evidence collection is:
- **Time-consuming** and error-prone
- **Lacks continuous monitoring** capabilities
- **Difficult to prove integrity** and origin of collected evidence
- **Challenging to maintain** chain of custody for audits and forensics

While AWS Config offers continuous monitoring, *Compliance Ledger* centralizes policy definition, performs critical evidence integrity checks, and provides unified, auditable output - making the compliance process truly verifiable and scalable.

## 🚀 Key Features (MVP)

### 1. **Policy-as-Code Definition**
- Define compliance controls in human-readable YAML
- Support for multiple frameworks (NIST CSF, SOC2, PCI DSS, ISO 27001, HIPAA)
- Flexible evidence collection methods

### 2. **Dual Evidence Collection Methods**
- **Direct API Calls**: Traditional boto3 service API calls
- **AWS Config Integration**: Leverage AWS Config Rules and Advanced Queries
- Intelligent routing based on policy definition

### 3. **Digital Evidence Integrity (Guardian's Mandate)**
- **SHA-256 Hashing**: Immediate cryptographic hashing of collected evidence
- **Trusted Timestamps**: UTC timestamps for collection verification
- **Evidence Bundles**: Secure packaging with metadata and integrity data
- **Immutable Storage Ready**: Designed for WORM storage systems

### 4. **Comprehensive Reporting**
- **JSON Reports**: Structured data for programmatic processing
- **Markdown Reports**: Human-readable audit reports
- **Evidence Source Tracking**: Clear identification of data source (direct API vs AWS Config)

### 5. **AWS Config Integration**
- **Config Rule Evaluations**: Query compliance status of AWS Config Rules
- **Advanced Queries**: SQL-like queries for complex resource filtering
- **Scalable Monitoring**: Leverage AWS Config's continuous monitoring capabilities

## 🛠️ Technologies Used

- **Python 3.8+**: Core programming language
- **boto3**: AWS SDK for Python
- **PyYAML**: YAML policy parsing
- **SHA-256**: Cryptographic hashing for evidence integrity
- **AWS Config**: Continuous compliance monitoring
- **S3 Object Lock**: Immutable storage concepts (production deployment)

## 📋 Prerequisites

### AWS Configuration
1. **AWS Credentials**: Configure AWS credentials via:
   - AWS CLI profiles
   - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
   - IAM roles (EC2, ECS, Lambda)
   - AWS SSO

2. **AWS Config Setup**: For AWS Config integration:
   - AWS Config must be enabled in target accounts/regions
   - Appropriate Config Rules should be configured
   - IAM permissions for Config API access

### Required IAM Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "config:GetComplianceDetailsByConfigRule",
                "config:SelectResourceConfig",
                "iam:GetCredentialReport",
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:ListRoles",
                "iam:ListPolicies",
                "s3:GetBucketEncryption",
                "s3:GetBucketPublicAccessBlock"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd tools/GRC_automation_scripts/compliance_ledger

# Install dependencies
pip install -r requirements.txt

# Make script executable
chmod +x compliance_ledger.py
```

### 2. Configure AWS Credentials

```bash
# Option 1: AWS CLI profile
aws configure --profile compliance-audit

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

### 3. Run Evidence Collection

```bash
# Basic usage with AWS Config integration
python compliance_ledger.py \
    --policy-file policies/example_aws_s3_encryption_config.yaml \
    --region us-east-1

# With AWS profile and markdown output
python compliance_ledger.py \
    --policy-file policies/example_aws_iam_mfa_api.yaml \
    --region us-west-2 \
    --profile production \
    --output-format markdown

# Verbose logging for debugging
python compliance_ledger.py \
    --policy-file policies/example_aws_s3_encryption_config.yaml \
    --region us-east-1 \
    --verbose
```

## 📝 Policy Definition Examples

### AWS Config Integration Example

```yaml
- control_id: "NIST_CSF_PR.DS-1"
  description: "Data-at-rest protection - S3 bucket encryption"
  cloud_provider: "aws"
  resource_type: "s3_bucket"
  evidence_collection_method:
    source_type: "aws_config_query"
    config_rule_name: "s3-bucket-server-side-encryption-enabled"
    compliance_status: "NON_COMPLIANT"
```

### Direct API Call Example

```yaml
- control_id: "NIST_CSF_PR.AC-4"
  description: "Access control - IAM user MFA compliance"
  cloud_provider: "aws"
  resource_type: "iam_user"
  evidence_collection_method:
    source_type: "api_call"
    service: "iam"
    api_call: "get_credential_report"
    parameters: {}
```

### AWS Config Advanced Query Example

```yaml
- control_id: "PCI_DSS_3.4"
  description: "Protect stored cardholder data"
  cloud_provider: "aws"
  resource_type: "s3_bucket"
  evidence_collection_method:
    source_type: "aws_config_query"
    advanced_query: |
      SELECT
        configurationItemId,
        resourceId,
        resourceName,
        configuration.serverSideEncryptionConfiguration
      WHERE
        resourceType = 'AWS::S3::Bucket'
        AND configuration.serverSideEncryptionConfiguration IS NULL
```

## 📊 Example Output

### Evidence Bundle Structure

```json
{
  "control_id": "NIST_CSF_PR.DS-1",
  "resource_type": "s3_bucket",
  "cloud_provider": "aws",
  "evidence_data": {
    "config_rule_name": "s3-bucket-server-side-encryption-enabled",
    "compliance_status": "NON_COMPLIANT",
    "evaluations": [...]
  },
  "evidence_source": "aws_config",
  "collection_tool_version": "1.0.0",
  "evidence_hash": "a1b2c3d4e5f6...",
  "collection_timestamp": "2024-01-15T10:30:00Z"
}
```

### Report Output

The tool generates comprehensive reports in both JSON and Markdown formats, including:

- **Evidence Source Tracking**: Clear identification of whether evidence came from direct API calls or AWS Config
- **Integrity Verification**: SHA-256 hashes for each evidence bundle
- **Audit Trail**: Complete timestamps and metadata
- **Control Mapping**: Evidence organized by compliance control

## 🔒 Security & Privacy Considerations

### Critical Security Principles

1. **READ-ONLY ACCESS ONLY**: The tool never performs modifying actions in cloud environments
2. **NO SENSITIVE DATA PROCESSING**: All example data is synthetic/anonymized
3. **SECURE CREDENTIAL MANAGEMENT**: AWS credentials should be managed securely (IAM roles, environment variables, profiles)
4. **PERFORMANCE & THROTTLING**: Implements boto3 best practices for API throttling

### Production Deployment Considerations

- **Immutable Storage**: Evidence bundles should be stored in S3 with Object Lock enabled
- **Network Security**: Use VPC endpoints for AWS API calls
- **Access Logging**: Enable CloudTrail for audit logging
- **Encryption**: Ensure all data is encrypted in transit and at rest

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Policy Files  │    │  Compliance      │    │   AWS Config    │
│   (YAML)        │───▶│  Ledger Engine   │───▶│   & Direct APIs │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Evidence      │    │  Cryptographic   │    │   Reports       │
│   Bundles       │◀───│  Integrity       │◀───│   (JSON/MD)     │
│   (Local)       │    │  Processing      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🔮 Future Enhancements

### Planned Features

1. **Multi-Cloud Support**: Extend beyond AWS to Azure, GCP
2. **Rego Validation**: Open Policy Agent (OPA) integration for policy validation
3. **True Ledger Integration**: Blockchain-based immutable ledger
4. **Advanced Reporting**: Interactive dashboards and trend analysis
5. **EventBridge Integration**: Real-time evidence collection
6. **Automated Remediation**: Policy violation response automation

### Roadmap

- **v1.1**: Multi-region support and batch processing
- **v1.2**: Azure and GCP integration
- **v2.0**: Real-time monitoring and alerting
- **v2.1**: Advanced policy validation with OPA
- **v3.0**: Blockchain ledger integration

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup development environment
git clone <repository-url>
cd tools/GRC_automation_scripts/compliance_ledger
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development dependencies

# Run tests
python -m pytest tests/

# Run linting
flake8 compliance_ledger.py
black compliance_ledger.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Important Disclaimers

### Production Use

- **WARNING: NOT PRODUCTION IMMUTABLE STORAGE**: Local evidence storage is for development/testing only
- **Production Deployment**: Use S3 Object Lock or similar WORM storage for production
- **Security Review**: Conduct thorough security review before production deployment

### AWS Config Prerequisites

- AWS Config must be enabled in target accounts/regions
- Appropriate Config Rules must be configured
- Sufficient IAM permissions for Config API access

## 📞 Support

For support, questions, or contributions:

- **Issues**: [GitHub Issues](https://github.com/your-org/compliance-ledger/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/compliance-ledger/discussions)
- **Documentation**: [Wiki](https://github.com/your-org/compliance-ledger/wiki)

---

**The Guardian's Forge** - Empowering organizations with robust, verifiable compliance automation.

*"In the realm of digital compliance, integrity is not optional - it is the foundation upon which trust is built."*