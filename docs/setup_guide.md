# Cloud Sentinel's Toolkit - Setup Guide

## Introduction

This guide will help you set up your development environment to work with Cloud Sentinel's Toolkit, a comprehensive collection of cloud security, GRC, and AI security tools. Whether you're contributing to the project or using the tools in your environment, this guide covers all necessary setup steps.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+), macOS (10.15+), or Windows 10/11 with WSL2
- **Python**: Version 3.8 or higher (3.10+ recommended)
- **Memory**: Minimum 8GB RAM (16GB recommended for AI tools)
- **Storage**: At least 10GB free space for dependencies and data
- **Network**: Internet connection for cloud API access and dependency downloads

### Required Accounts and Credentials

You'll need accounts with cloud providers to use the security assessment tools:

- **AWS Account**: For AWS-specific tools (IAM analysis, Config rule evaluation)
- **Azure Account**: For Azure security assessment tools
- **Google Cloud Account**: For GCP security analysis tools
- **OpenAI/Anthropic API Keys**: For LLM security proxy (optional)

## Core Environment Setup

### 1. Python Environment Setup

#### Using pyenv (Recommended)

```bash
# Install pyenv (Linux/macOS)
curl https://pyenv.run | bash

# Add to shell profile
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc

# Restart shell or source profile
source ~/.bashrc

# Install Python 3.10
pyenv install 3.10.12
pyenv global 3.10.12
```

#### Using conda (Alternative)

```bash
# Install miniconda
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh

# Create environment
conda create -n cloud-sentinel python=3.10
conda activate cloud-sentinel
```

### 2. Git and Repository Setup

```bash
# Clone the repository
git clone https://github.com/your-org/Cloud-Sentinels-Toolkit.git
cd Cloud-Sentinels-Toolkit

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip
```

### 3. Core Dependencies Installation

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Verify installation
python --version
pip list
```

## Cloud Provider Setup

### AWS Configuration

#### 1. Install AWS CLI

```bash
# Linux/macOS
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version
```

#### 2. Configure AWS Credentials

```bash
# Interactive configuration
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### 3. Create IAM User for Security Tools

Create an IAM user with the following managed policies:
- `SecurityAudit` (AWS managed policy)
- `ConfigUserAccess` (for Config rule access)

Custom policy for additional permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "cloudtrail:DescribeTrails",
                "config:GetComplianceDetailsByConfigRule",
                "config:DescribeConfigRules"
            ],
            "Resource": "*"
        }
    ]
}
```

### Azure Configuration

#### 1. Install Azure CLI

```bash
# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# macOS
brew install azure-cli

# Verify installation
az --version
```

#### 2. Login and Setup

```bash
# Login to Azure
az login

# Set default subscription
az account set --subscription "your-subscription-id"

# Create service principal for automation
az ad sp create-for-rbac --name "CloudSentinelToolkit" --role "Security Reader"
```

### Google Cloud Configuration

#### 1. Install Google Cloud SDK

```bash
# Linux/macOS
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Initialize gcloud
gcloud init
```

#### 2. Authentication Setup

```bash
# Login to Google Cloud
gcloud auth login

# Set project
gcloud config set project your-project-id

# Create service account
gcloud iam service-accounts create cloud-sentinel-toolkit \
    --description="Service account for Cloud Sentinel Toolkit" \
    --display-name="Cloud Sentinel Toolkit"

# Create and download key
gcloud iam service-accounts keys create key.json \
    --iam-account=cloud-sentinel-toolkit@your-project-id.iam.gserviceaccount.com

# Set environment variable
export GOOGLE_APPLICATION_CREDENTIALS="path/to/key.json"
```

## Tool-Specific Setup

### Security Assessment Tools

```bash
# Navigate to tools directory
cd tools/

# Install tool-specific dependencies
pip install boto3 networkx pandas matplotlib
pip install azure-identity azure-mgmt-network
pip install google-cloud-compute
```

### LLM Security Proxy

```bash
# Navigate to project directory
cd projects/secure_llm_proxy/

# Install web framework dependencies
pip install fastapi uvicorn redis

# Install ML dependencies for PII detection
pip install spacy transformers torch
python -m spacy download en_core_web_sm

# Set up Redis (Ubuntu/Debian)
sudo apt-get install redis-server
sudo systemctl start redis-server

# Set up Redis (macOS)
brew install redis
brew services start redis
```

### AI Security Tools

```bash
# Navigate to AI tools directory
cd tools/ai_security_helpers/

# Install machine learning dependencies
pip install scikit-learn numpy pandas matplotlib seaborn
pip install jupyter notebook plotly

# For advanced ML features (optional)
pip install tensorflow torch torchvision
```

## Development Environment Configuration

### Code Quality Tools

```bash
# Install and configure code formatters
pip install black isort flake8 mypy

# Create pre-commit configuration (already included)
# Verify pre-commit hooks
pre-commit run --all-files
```

### Security Tools

```bash
# Install security scanning tools
pip install bandit safety semgrep

# Run security checks
bandit -r . -f json
safety check
```

### Testing Setup

```bash
# Install testing frameworks
pip install pytest pytest-cov pytest-mock pytest-asyncio

# Run tests
pytest tests/ -v --cov=.
```

## Environment Variables

Create a `.env` file in the project root:

```bash
# Cloud Credentials
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=us-east-1

AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_TENANT_ID=your_azure_tenant_id

GOOGLE_APPLICATION_CREDENTIALS=/path/to/gcp/key.json

# LLM API Keys (optional)
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Logging Configuration
LOG_LEVEL=INFO
LOG_FORMAT=json
```

## IDE and Editor Setup

### Visual Studio Code

Recommended extensions:

```json
{
    "recommendations": [
        "ms-python.python",
        "ms-python.flake8",
        "ms-python.black-formatter",
        "ms-python.isort",
        "ms-python.mypy-type-checker",
        "ms-vscode.vscode-json",
        "redhat.vscode-yaml",
        "ms-vscode.azure-account",
        "amazonwebservices.aws-toolkit-vscode"
    ]
}
```

### PyCharm

1. Open project in PyCharm
2. Configure Python interpreter to use the virtual environment
3. Enable code inspections for security and quality
4. Install plugins: AWS Toolkit, Azure Toolkit

## Verification

Run the following commands to verify your setup:

```bash
# Check Python and pip versions
python --version
pip --version

# Verify cloud CLI tools
aws --version
az --version
gcloud --version

# Test cloud authentication
aws sts get-caller-identity
az account show
gcloud auth list

# Run basic security checks
bandit --version
safety --version

# Test tool imports
python -c "import boto3; print('AWS SDK: OK')"
python -c "import azure.identity; print('Azure SDK: OK')"
python -c "import google.cloud; print('GCP SDK: OK')"

# Run a simple test
pytest tests/ -v
```

## Troubleshooting

### Common Issues

#### Permission Errors

```bash
# Fix pip permissions
pip install --user package_name

# Or use virtual environment
python -m venv venv
source venv/bin/activate
```

#### Cloud Authentication Issues

```bash
# Clear AWS credentials cache
aws configure list
rm -rf ~/.aws/credentials

# Re-authenticate Azure
az logout
az login

# Refresh GCP tokens
gcloud auth revoke
gcloud auth login
```

#### Dependency Conflicts

```bash
# Create fresh virtual environment
deactivate
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Getting Help

1. **Check the documentation**: Each tool has detailed README files
2. **Review GitHub Issues**: Search for similar problems
3. **Check cloud provider documentation**: For authentication and permission issues
4. **Create an issue**: If you find a bug or need help

## Next Steps

After completing the setup:

1. **Read the documentation**: Start with `docs/personal_philosophy.md`
2. **Explore the tools**: Begin with simpler tools like network auditors
3. **Run examples**: Each tool includes usage examples
4. **Contribute**: See `CONTRIBUTING.md` for contribution guidelines

## Security Notes

- Never commit credentials to version control
- Use environment variables or credential files for sensitive information
- Regularly rotate API keys and access tokens
- Follow cloud provider security best practices
- Keep dependencies updated for security patches

---

*"A properly configured environment is the foundation of effective security tooling. Take time to set it up correctly for the best experience."*