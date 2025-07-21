# Quick Start Guide
## Secure LLM Interaction Proxy

This guide will help you get the Secure LLM Proxy up and running quickly with enterprise authentication.

## 🚀 Quick Deployment

### 1. Prerequisites

Ensure you have the following installed:
- Python 3.8+
- pip
- git

### 2. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd llm_secure_proxy

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Initial Configuration

```bash
# Create environment file
cp .env.example .env

# Edit configuration
nano .env
```

Update the `.env` file with your settings:

```env
# Application Configuration
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=your-super-secret-key-here

# Security Configuration
AUTHENTICATION_REQUIRED=true
API_KEY_VALIDATION=true
SSL_VERIFY=false
AUDIT_ENCRYPTION_ENABLED=false
AUDIT_BACKUP_ENABLED=false

# External Services
LLM_API_KEY=your-openai-api-key
LLM_API_URL=https://api.openai.com/v1

# Monitoring
LOG_LEVEL=INFO
```

### 4. Create Admin User

```bash
# Create the first admin user
python manage.py create-admin --username admin --email admin@yourcompany.com
```

### 5. Start the Application

```bash
# Development mode
python app.py

# Or with gunicorn for production-like environment
gunicorn --workers 2 --bind 0.0.0.0:5000 app:app
```

The application will be available at `http://localhost:5000`

## 🔐 Authentication Setup

### User Management

```bash
# Create additional users
python manage.py create-user --username john --email john@company.com --role user

# List all users
python manage.py list-users

# Lock/unlock users
python manage.py lock-user --username john
python manage.py unlock-user --username john
```

### API Key Management

```bash
# Create API key for a user
python manage.py create-api-key --username john --name "Production Key"

# List user's API keys
python manage.py list-api-keys --username john

# Revoke an API key
python manage.py revoke-api-key --username john --key-id <key-id>
```

### Password Management

```bash
# Change user password
python manage.py change-password --username john

# Reset user password (admin only)
python manage.py reset-password --username john
```

## 📊 Monitoring and Administration

### System Status

```bash
# Check system status
python manage.py show-status

# View recent authentication events
python manage.py show-events --limit 20

# Clean up expired sessions
python manage.py cleanup-sessions
```

## 🔧 API Usage

### Authentication Methods

#### 1. API Key Authentication (Recommended)

```bash
curl -X POST http://localhost:5000/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{
    "message": "Hello, how are you?",
    "model": "gpt-3.5-turbo"
  }'
```

#### 2. Session Authentication

```bash
# First, login to get session token
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "password": "your-password"
  }'

# Use session token for subsequent requests
curl -X POST http://localhost:5000/chat \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your-session-token" \
  -d '{
    "message": "Hello, how are you?",
    "model": "gpt-3.5-turbo"
  }'
```

### Available Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/health` | GET | Health check | No |
| `/security/status` | GET | Security status | Yes |
| `/chat` | POST | Chat with LLM | Yes |
| `/audit/validate` | GET | Validate audit trail | Yes |
| `/audit/export` | GET | Export audit logs | Yes |

## 🛡️ Security Features

### Built-in Security

- **Input Validation**: All inputs are validated and sanitized
- **Rate Limiting**: Configurable rate limiting per user/IP
- **Content Filtering**: Harmful content detection and filtering
- **PII Redaction**: Automatic PII detection and redaction
- **Audit Logging**: Comprehensive audit trail for compliance
- **Session Management**: Secure session handling with timeouts
- **MFA Support**: Optional multi-factor authentication
- **API Key Management**: Secure API key generation and management

### Security Headers

The application automatically includes security headers:
- Content Security Policy (CSP)
- Strict Transport Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer Policy

## 📋 Production Deployment

For production deployment, follow the comprehensive guide in `DEPLOYMENT_GUIDE.md`:

1. **System Setup**: Configure production server with proper security
2. **SSL/TLS**: Set up SSL certificates
3. **Database**: Configure PostgreSQL for production
4. **Monitoring**: Set up logging and monitoring
5. **Backup**: Configure automated backups
6. **Firewall**: Configure network security

### Quick Production Checklist

- [ ] SSL certificates installed
- [ ] Environment variables configured
- [ ] Database initialized
- [ ] Admin user created
- [ ] Firewall configured
- [ ] Monitoring enabled
- [ ] Backup procedures in place

## 🔍 Troubleshooting

### Common Issues

#### 1. Authentication Errors

```bash
# Check user status
python manage.py list-users

# Check authentication events
python manage.py show-events --limit 10
```

#### 2. API Key Issues

```bash
# List user's API keys
python manage.py list-api-keys --username <username>

# Create new API key if needed
python manage.py create-api-key --username <username> --name "New Key"
```

#### 3. Database Issues

```bash
# Check system status
python manage.py show-status

# Clean up sessions
python manage.py cleanup-sessions
```

### Logs

Check application logs for detailed error information:

```bash
# Application logs
tail -f logs/app.log

# Audit logs
tail -f logs/audit.jsonl
```

## 📚 Next Steps

1. **Read the Documentation**:
   - `README.md` - Complete feature overview
   - `DEPLOYMENT_GUIDE.md` - Production deployment
   - `SECURITY_BEST_PRACTICES.md` - Security guidelines

2. **Configure External LLM**:
   - Set up your LLM API credentials
   - Configure model parameters
   - Test with your specific use case

3. **Customize Security**:
   - Adjust rate limiting settings
   - Configure content filtering rules
   - Set up custom audit requirements

4. **Monitor and Maintain**:
   - Set up monitoring alerts
   - Regular security reviews
   - Update dependencies

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the comprehensive documentation
3. Check the logs for detailed error information
4. Ensure all prerequisites are met

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Version**: 1.0  
**Last Updated**: 2024  
**Security Level**: Production-Ready  
**Compliance Status**: Multi-Framework Ready