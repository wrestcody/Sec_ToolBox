# AWS IAM Privilege Escalation Path Finder

## Overview

The AWS IAM Privilege Escalation Path Finder is an advanced security assessment tool that analyzes AWS Identity and Access Management (IAM) configurations to identify potential privilege escalation paths. Using graph-based analysis, it maps relationships between IAM entities and identifies chains of permissions that could allow an attacker to gain higher privileges than intended.

## Portfolio Showcase

This tool demonstrates several key skills and expertise areas:

- **Deep AWS IAM Understanding**: Comprehensive knowledge of IAM policies, roles, trust relationships, and permission boundaries
- **Graph Theory Application**: Implementation of graph algorithms for security analysis
- **Attack Vector Analysis**: Ability to think like an attacker and identify potential exploitation paths
- **Secure API Integration**: Proper AWS SDK usage with security best practices
- **Risk Scoring**: Quantitative assessment of security risks based on privilege escalation potential

## Trend Alignment

### Zero Trust Architecture
- **Least Privilege Validation**: Ensures IAM configurations align with principle of least privilege
- **Continuous Verification**: Provides ongoing assessment of trust relationships and permissions
- **Risk-Based Access**: Identifies permissions that could enable unauthorized lateral movement

### Cloud Security Posture Management (CSPM)
- **Configuration Assessment**: Automated analysis of IAM security posture
- **Continuous Monitoring**: Regular evaluation of permission changes and their security impact
- **Compliance Support**: Validates IAM configurations against security frameworks

## Features (MVP)

### Core Functionality

1. **IAM Entity Discovery**
   - Enumerate all IAM users, roles, groups, and policies in AWS account
   - Map direct and inherited permissions for each entity
   - Identify service-linked roles and their permissions

2. **Privilege Escalation Path Analysis**
   - Detect permissions that allow modification of IAM policies
   - Identify role assumption chains that lead to higher privileges
   - Find policies that grant broad administrative access

3. **Graph-Based Relationship Mapping**
   - Build directed graph of IAM entities and their relationships
   - Identify shortest paths to administrative privileges
   - Visualize complex permission inheritance chains

4. **Risk Scoring and Prioritization**
   - Calculate risk scores based on potential impact and exploitability
   - Prioritize findings by likelihood of successful exploitation
   - Provide actionable remediation recommendations

5. **Comprehensive Reporting**
   - Generate detailed reports with technical findings and business impact
   - Export results in multiple formats (JSON, CSV, HTML)
   - Include evidence and remediation steps for each finding

### Advanced Features (Future Enhancements)

- **Cross-Account Analysis**: Analyze privilege escalation paths across AWS accounts
- **Temporal Analysis**: Track permission changes over time to identify trends
- **Integration APIs**: REST API for integration with security orchestration platforms
- **Custom Policy Simulation**: Test hypothetical policy changes for security impact

## Security & Privacy Considerations

### Security-First Design

- **Read-Only Operations**: Tool only reads IAM configurations, never modifies them
- **Minimal Permissions**: Requires only necessary IAM read permissions
- **Credential Protection**: Supports AWS credential best practices (IAM roles, temporary credentials)
- **Audit Logging**: All API calls are logged for security auditing

### Privacy Protection

- **Metadata Focus**: Analyzes IAM structure and policies, not user data
- **Data Minimization**: Collects only IAM configuration data necessary for analysis
- **No Data Persistence**: Option to run without storing sensitive data locally
- **Anonymization Options**: Can anonymize entity names in reports for sharing

### Compliance Considerations

- **GDPR Compliance**: No processing of personal data beyond IAM metadata
- **SOC 2 Support**: Audit logging and access controls support compliance requirements
- **Industry Standards**: Aligns with CIS AWS Foundations Benchmark recommendations

## Usage

### Prerequisites

```bash
# Install required Python packages
pip install boto3 networkx pandas matplotlib

# Configure AWS credentials (choose one method)
aws configure                           # AWS CLI
export AWS_ACCESS_KEY_ID=your_key      # Environment variables
# Or use IAM roles (recommended for production)
```

### Required AWS Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListGroups",
                "iam:ListPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedGroupPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetUser",
                "iam:GetRole",
                "iam:GetGroup"
            ],
            "Resource": "*"
        }
    ]
}
```

### Basic Usage

```bash
# Run privilege escalation analysis
python iam_privilege_escalation_finder.py

# Generate report with specific output format
python iam_privilege_escalation_finder.py --output-format html --output-file escalation_report.html

# Analyze specific IAM entities
python iam_privilege_escalation_finder.py --target-entities arn:aws:iam::123456789012:user/analyst

# Run with custom risk thresholds
python iam_privilege_escalation_finder.py --risk-threshold medium --max-depth 5
```

### Advanced Usage

```python
from iam_privilege_escalation_finder import IAMPrivilegeAnalyzer

# Initialize analyzer
analyzer = IAMPrivilegeAnalyzer(region='us-east-1')

# Run comprehensive analysis
results = analyzer.analyze_privilege_escalation_paths()

# Filter high-risk findings
high_risk_paths = analyzer.filter_by_risk_score(results, min_score=7.0)

# Generate custom report
analyzer.generate_report(high_risk_paths, format='json', output_file='high_risk_paths.json')
```

## Development Notes

### Project Structure

```
aws_iam_privilege_escalation_finder/
├── README.md                           # This file
├── requirements.txt                    # Python dependencies
├── iam_privilege_escalation_finder.py  # Main application
├── src/
│   ├── __init__.py
│   ├── iam_analyzer.py                 # Core analysis logic
│   ├── graph_builder.py               # Graph construction and analysis
│   ├── risk_calculator.py             # Risk scoring algorithms
│   └── report_generator.py            # Report generation
├── tests/
│   ├── __init__.py
│   ├── test_iam_analyzer.py
│   ├── test_graph_builder.py
│   └── test_risk_calculator.py
├── examples/
│   ├── sample_analysis.py
│   └── sample_config.json
└── docs/
    ├── api_documentation.md
    └── privilege_escalation_patterns.md
```

### Key Dependencies

```txt
boto3>=1.26.0                 # AWS SDK for Python
networkx>=3.0                 # Graph analysis library
pandas>=1.5.0                 # Data manipulation and analysis
matplotlib>=3.6.0             # Visualization for reports
click>=8.0.0                  # Command-line interface
jinja2>=3.1.0                 # Template engine for reports
pydantic>=1.10.0              # Data validation
pytest>=7.0.0                 # Testing framework
pytest-cov>=4.0.0             # Test coverage
black>=22.0.0                 # Code formatting
flake8>=5.0.0                 # Linting
bandit>=1.7.0                 # Security linting
```

### Testing Strategy

- **Unit Tests**: Test individual components (analyzers, calculators, builders)
- **Integration Tests**: Test AWS API integration with mock responses
- **Security Tests**: Validate secure handling of credentials and sensitive data
- **Performance Tests**: Ensure scalability for large AWS environments

### Contribution Guidelines

1. **Security First**: All changes must maintain or improve security posture
2. **Test Coverage**: Maintain >90% test coverage for new code
3. **Documentation**: Update documentation for any new features
4. **Performance**: Consider impact on large AWS environments
5. **Compatibility**: Ensure compatibility with supported Python versions (3.8+)

## Related Resources

### AWS Security Documentation
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Security Blog - IAM](https://aws.amazon.com/blogs/security/category/security-identity-compliance/aws-identity-and-access-management/)
- [IAM Policy Evaluation Logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)

### Security Research and Tools
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Config Rules for IAM](https://docs.aws.amazon.com/config/latest/developerguide/iam-config-rules.html)

---

*"Understanding privilege escalation paths is crucial for maintaining the principle of least privilege and preventing unauthorized access in cloud environments."*