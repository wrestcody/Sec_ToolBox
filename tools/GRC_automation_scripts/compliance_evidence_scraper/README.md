# Cloud Compliance Evidence Scraper

A Python CLI tool that automates the collection of specific configuration and log data from AWS (and conceptually other clouds) that serves as auditable evidence for common compliance controls. This tool aims to streamline audit preparation and demonstrate "compliance-as-code" principles.

## ⚠️ CRITICAL SECURITY WARNINGS

**This tool performs READ-ONLY operations only. It should NEVER modify cloud configurations.**

**IMPORTANT SECURITY CONSIDERATIONS:**
- This tool only performs read-only API calls to collect configuration and metadata
- **NO sensitive or production data is processed or stored** in the public repository
- All examples and test data are anonymized or synthetic
- The tool focuses on configuration status and aggregate counts rather than raw log content
- **Never run this tool with credentials that have write permissions** unless absolutely necessary

## Features

### 🔒 Compliance Framework Support
- **SOC 2**: Common Criteria (CC) controls for access management and monitoring
- **ISO 27001**: Information security controls for logging, monitoring, and data protection
- **PCI DSS**: Payment card industry controls for data encryption and access control
- **NIST Cybersecurity Framework**: Identity management and continuous monitoring controls
- **AWS Best Practices**: Cloud-specific security controls

### 🛡️ Evidence Collection
- **IAM Controls**: MFA status, password policies, administrative user identification
- **S3 Security**: Bucket encryption, versioning, and access controls
- **CloudTrail Monitoring**: Trail configuration, logging status, multi-region coverage
- **RDS Protection**: Database encryption status and KMS key usage

### 📊 Multiple Output Formats
- **JSON**: Structured data for programmatic processing
- **Markdown**: Human-readable reports for audit documentation
- **CSV**: Tabular data for spreadsheet analysis

### 🔧 Configurable Controls
- YAML-based control mapping for easy customization
- Framework-specific filtering
- Individual control targeting
- Extensible architecture for new compliance frameworks

## Installation

### Prerequisites
- Python 3.8 or higher
- AWS credentials configured (see [AWS Credentials Setup](#aws-credentials-setup))
- Appropriate AWS permissions (see [Required Permissions](#required-permissions))

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd tools/GRC_automation_scripts/compliance_evidence_scraper

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x compliance_scraper.py
```

## AWS Credentials Setup

### Option 1: AWS CLI Configuration (Recommended)
```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and default region
```

### Option 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

### Option 3: IAM Role (for EC2 instances)
If running on an EC2 instance, attach an IAM role with the required permissions.

## Required Permissions

The tool requires the following AWS permissions (read-only):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListAttachedUserPolicies",
                "s3:ListBuckets",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "cloudtrail:ListTrails",
                "cloudtrail:GetTrail",
                "cloudtrail:GetTrailStatus",
                "rds:DescribeDBInstances",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Usage
```bash
# Collect evidence for all controls
python compliance_scraper.py --config controls_mapping.yaml

# Collect evidence for specific framework
python compliance_scraper.py --config controls_mapping.yaml --framework "SOC 2"

# Collect evidence for specific controls
python compliance_scraper.py --config controls_mapping.yaml --control-ids CC6.1 CC6.2

# Specify AWS region
python compliance_scraper.py --config controls_mapping.yaml --region us-west-2
```

### Output Options
```bash
# Generate JSON report
python compliance_scraper.py --config controls_mapping.yaml --output-format json

# Generate markdown report
python compliance_scraper.py --config controls_mapping.yaml --output-format markdown --output-file report.md

# Generate CSV report
python compliance_scraper.py --config controls_mapping.yaml --output-format csv --output-file evidence.csv
```

### Verbose Logging
```bash
# Enable detailed logging
python compliance_scraper.py --config controls_mapping.yaml --verbose
```

## Configuration

### Controls Mapping File (`controls_mapping.yaml`)

The tool uses a YAML configuration file to map compliance controls to AWS API calls. Each control defines:

- **Control ID**: Unique identifier (e.g., "CC6.1")
- **Framework**: Compliance framework (e.g., "SOC 2")
- **Type**: AWS service type (e.g., "iam", "s3", "cloudtrail")
- **Checks**: Specific evidence collection methods
- **Evidence Requirements**: What data should be collected
- **Risk Level**: Control risk assessment
- **Remediation Guidance**: Suggested fixes for issues

### Example Control Definition
```yaml
- id: "CC6.1"
  name: "Logical access is restricted to authorized users"
  framework: "SOC 2"
  category: "CC - Control Activities"
  type: "iam"
  description: "Verify that logical access is properly restricted"
  checks:
    - "mfa_root_check"
    - "password_policy_check"
    - "admin_users_check"
  evidence_requirements:
    - "Root account MFA status"
    - "IAM password policy configuration"
  risk_level: "High"
  remediation_guidance: "Enable MFA for root account, configure strong password policy"
```

## Extending the Tool

### Adding New Compliance Frameworks

1. **Define Controls**: Add new control definitions to `controls_mapping.yaml`
2. **Implement Evidence Collection**: Add new methods to the `ComplianceEvidenceScraper` class
3. **Update Configuration**: Add framework-specific settings

### Adding New AWS Services

1. **Initialize Client**: Add new AWS client in `_initialize_aws_clients()`
2. **Create Collection Method**: Implement `_collect_<service>_evidence()` method
3. **Update Control Types**: Add new service type to control definitions
4. **Add Evidence Methods**: Define new evidence collection methods in YAML

### Example: Adding EC2 Security Group Checks
```python
def _collect_ec2_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
    """Collect EC2-related evidence for compliance controls."""
    evidence = {
        'control_id': control['id'],
        'control_name': control['name'],
        'evidence_type': 'ec2',
        'timestamp': datetime.utcnow().isoformat(),
        'data': {}
    }
    
    # Implement EC2-specific checks
    if 'security_group_check' in control.get('checks', []):
        # Add security group validation logic
        pass
    
    return evidence
```

## Security Best Practices

### Credential Management
- Use IAM roles when possible instead of access keys
- Rotate access keys regularly
- Use least privilege principle for IAM permissions
- Never commit credentials to version control

### Data Handling
- The tool only collects configuration metadata, not sensitive data
- All output is sanitized to remove sensitive information
- Use aggregate counts for user lists and sensitive resources
- Implement proper access controls on generated reports

### Network Security
- Run the tool from secure, trusted networks
- Use VPN or private subnets when accessing AWS resources
- Monitor API calls through CloudTrail
- Implement proper logging and alerting

## Troubleshooting

### Common Issues

**AWS Credentials Not Found**
```bash
Error: AWS credentials not found. Please configure your AWS credentials.
```
**Solution**: Configure AWS credentials using `aws configure` or environment variables.

**Permission Denied**
```bash
Error: An error occurred (AccessDenied) when calling the GetAccountSummary operation
```
**Solution**: Ensure your IAM user/role has the required read permissions.

**No Controls Found**
```bash
Warning: No controls found matching the specified criteria
```
**Solution**: Check your framework name or control IDs in the configuration file.

**YAML Parsing Error**
```bash
Error: Error parsing YAML file: mapping values are not allowed here
```
**Solution**: Validate your YAML syntax using a YAML validator.

### Debug Mode
```bash
# Enable debug logging
python compliance_scraper.py --config controls_mapping.yaml --verbose
```

## Contributing

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest

# Format code
black compliance_scraper.py

# Lint code
flake8 compliance_scraper.py

# Type checking
mypy compliance_scraper.py
```

### Code Style
- Follow PEP 8 style guidelines
- Use type hints for all function parameters and return values
- Add docstrings for all public methods
- Include error handling for all AWS API calls

### Testing
- Write unit tests for new evidence collection methods
- Test with different AWS account configurations
- Validate output formats and data sanitization
- Test error handling and edge cases

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided as-is for educational and compliance automation purposes. Users are responsible for:

- Ensuring proper AWS credentials and permissions
- Validating collected evidence for accuracy
- Following their organization's security policies
- Complying with applicable data protection regulations
- Using the tool in accordance with AWS terms of service

The authors are not responsible for any misuse of this tool or any consequences resulting from its use.

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section above
2. Review the configuration examples
3. Validate your AWS permissions
4. Open an issue with detailed error information

## Roadmap

### Planned Features
- Support for additional cloud providers (Azure, GCP)
- Integration with compliance management platforms
- Automated remediation suggestions
- Historical evidence tracking
- Custom compliance framework definitions
- Web-based dashboard for evidence visualization

### Future Enhancements
- Machine learning-based anomaly detection
- Integration with SIEM platforms
- Automated compliance reporting
- Real-time monitoring capabilities
- Multi-account support
- Compliance score calculation