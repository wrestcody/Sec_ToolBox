# 🚀 Quick Start Guide - Guardians Armory

Welcome to Guardians Armory! This guide will help you get started with the most important tools and features.

## 📋 Prerequisites

- **Python 3.8+** (check with `python --version`)
- **Git** (for cloning the repository)
- **Basic understanding of cybersecurity concepts**

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Sec_ToolBox.git
cd Sec_ToolBox
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Verify Installation

```bash
python -c "import cryptography; print('✅ Dependencies installed successfully')"
```

## 🎯 Your First 5 Minutes

### 1. **Network Scanner** (2 minutes)

Scan your local network to see what's connected:

```bash
# Scan your local network
python tools/security_armory/network_scanner/network_scanner.py 192.168.1.0/24

# Scan specific ports on a single host
python tools/security_armory/network_scanner/network_scanner.py 192.168.1.1 -p 22,80,443

# Save results to file
python tools/security_armory/network_scanner/network_scanner.py 192.168.1.0/24 -o scan_results.json
```

**What you'll learn:** Basic network reconnaissance, port scanning, service detection

### 2. **Password Analyzer** (1 minute)

Test password strength and security:

```bash
# Analyze a single password
python tools/security_armory/password_analyzer/password_analyzer.py "mypassword123"

# Analyze passwords from a file
echo -e "password123\nMySecurePass!2024\nqwerty" > test_passwords.txt
python tools/security_armory/password_analyzer/password_analyzer.py -f test_passwords.txt
```

**What you'll learn:** Password security best practices, entropy calculation, attack time estimation

### 3. **Guardian's Mandate Demo** (2 minutes)

See the advanced cryptographic integrity features:

```bash
# Run the comprehensive demo
python grc_engineering_demo.py

# Or run individual components
python guardians_mandate.py --demo
```

**What you'll learn:** Cryptographic audit trails, chain of custody, forensic readiness

## 🛠️ Essential Tools Overview

### 🔍 **Network Security Tools**

| Tool | Purpose | Command |
|------|---------|---------|
| Network Scanner | Discover hosts and open ports | `python tools/security_armory/network_scanner/network_scanner.py <target>` |
| IAM Anomaly Detector | Detect suspicious cloud access | `python tools/guardians_armory/iam_anomaly_detector/iam_anomaly_detector.py` |

### 🔐 **Security Analysis Tools**

| Tool | Purpose | Command |
|------|---------|---------|
| Password Analyzer | Assess password strength | `python tools/security_armory/password_analyzer/password_analyzer.py <password>` |
| Threat Intelligence | Analyze security threats | `python tools/security_armory/threat_intelligence_analyzer/threat_intelligence_analyzer.py` |

### 📊 **GRC & Compliance Tools**

| Tool | Purpose | Command |
|------|---------|---------|
| GRC MCP Server | AI-powered compliance assistant | `python grc_mcp_server.py` |
| Compliance Ledger | Automated evidence collection | `python tools/GRC_automation_scripts/compliance_ledger/compliance_ledger.py` |

## 🎓 Learning Path

### **Beginner (First Week)**
1. **Day 1-2:** Network Scanner - Understand basic reconnaissance
2. **Day 3-4:** Password Analyzer - Learn password security
3. **Day 5-7:** Guardian's Mandate Demo - See advanced features

### **Intermediate (Second Week)**
1. **Day 1-3:** IAM Anomaly Detector - Cloud security concepts
2. **Day 4-5:** GRC MCP Server - AI integration
3. **Day 6-7:** Custom tool development

### **Advanced (Third Week+)**
1. **Week 3:** Build your own tools using Guardian's Mandate
2. **Week 4:** Integrate with your existing security tools
3. **Week 5+:** Contribute to the project

## 🔧 Common Use Cases

### **Security Assessment**
```bash
# 1. Network reconnaissance
python tools/security_armory/network_scanner/network_scanner.py 10.0.0.0/24

# 2. Password audit
python tools/security_armory/password_analyzer/password_analyzer.py -f user_passwords.txt

# 3. Cloud IAM analysis
python tools/guardians_armory/iam_anomaly_detector/iam_anomaly_detector.py --log-file cloudtrail.json
```

### **Compliance Preparation**
```bash
# 1. Start GRC assistant
python grc_mcp_server.py

# 2. Collect compliance evidence
python tools/GRC_automation_scripts/compliance_ledger/compliance_ledger.py --framework SOC2

# 3. Generate audit report
python tools/data_privacy_tools/cloud_compliance_evidence_collector/collector.py
```

### **Forensic Investigation**
```bash
# 1. Enable Guardian's Mandate for all tools
export GUARDIAN_MANDATE_ENABLED=true

# 2. Run security analysis with audit trails
python tools/security_armory/network_scanner/network_scanner.py 192.168.1.0/24

# 3. Export forensic data
python guardians_mandate.py --export-forensic-data
```

## 🚨 Troubleshooting

### **Common Issues**

#### 1. Import Errors
```bash
# Solution: Install dependencies
pip install -r requirements.txt

# If still having issues:
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

#### 2. Guardian's Mandate Not Available
```bash
# This is normal - tools work in basic mode
# To enable Guardian's Mandate:
python guardians_mandate.py --setup
```

#### 3. Permission Errors (Network Scanner)
```bash
# On Linux/Mac, you might need elevated privileges
sudo python tools/security_armory/network_scanner/network_scanner.py 192.168.1.0/24

# Or use a smaller network range
python tools/security_armory/network_scanner/network_scanner.py 192.168.1.1
```

### **Getting Help**

1. **Check the logs:** Most tools create detailed logs
2. **Run with verbose mode:** Add `--verbose` to most commands
3. **Check documentation:** See individual tool READMEs
4. **Open an issue:** Use GitHub issues for bugs

## 🎯 Next Steps

### **For Security Professionals**
1. **Integrate with your workflow:** Add tools to your security toolkit
2. **Customize Guardian's Mandate:** Adapt to your compliance requirements
3. **Build custom tools:** Use the framework for your specific needs

### **For Students/Learners**
1. **Study the code:** Each tool is well-documented and educational
2. **Experiment safely:** Use on your own networks and test environments
3. **Contribute:** Submit improvements and new tools

### **For Organizations**
1. **Pilot program:** Start with one tool in a test environment
2. **Compliance mapping:** Map tools to your specific compliance needs
3. **Integration planning:** Plan how to integrate with existing tools

## 📚 Additional Resources

- **[Setup Guide](setup_guide.md)** - Detailed environment setup
- **[Contribution Guide](contribution_guide.md)** - How to contribute
- **[Personal Philosophy](personal_philosophy.md)** - My approach to security
- **[Trend Analysis](trends_analysis/)** - Security trends and insights

## 🤝 Community

- **GitHub Discussions:** Ask questions and share ideas
- **Issues:** Report bugs and request features
- **Pull Requests:** Contribute improvements
- **Security:** Report security vulnerabilities privately

---

**Ready to start?** Pick a tool from the "Your First 5 Minutes" section and dive in!

**Questions?** Check the troubleshooting section or open a GitHub issue.

**Want to contribute?** See the [Contribution Guide](contribution_guide.md) for details.