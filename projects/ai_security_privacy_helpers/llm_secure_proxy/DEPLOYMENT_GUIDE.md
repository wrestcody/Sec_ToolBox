# Production Deployment Guide
## Secure LLM Interaction Proxy

### Overview

This guide provides comprehensive instructions for deploying the Secure LLM Proxy in production environments with enterprise-grade security, monitoring, and compliance features.

### Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Security Configuration](#security-configuration)
4. [Authentication Setup](#authentication-setup)
5. [SSL/TLS Configuration](#ssltls-configuration)
6. [Database Setup](#database-setup)
7. [Monitoring and Logging](#monitoring-and-logging)
8. [Deployment Options](#deployment-options)
9. [Production Checklist](#production-checklist)
10. [Operational Procedures](#operational-procedures)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 20 GB SSD
- **Network**: 100 Mbps

#### Recommended Requirements
- **CPU**: 4+ cores, 2.5+ GHz
- **RAM**: 8+ GB
- **Storage**: 100+ GB SSD
- **Network**: 1 Gbps

#### Software Requirements
- **Operating System**: Ubuntu 20.04+ / CentOS 8+ / RHEL 8+
- **Python**: 3.8+
- **Redis**: 6.0+ (for production rate limiting)
- **PostgreSQL**: 12+ (for audit logs)
- **Nginx**: 1.18+ (reverse proxy)
- **Docker**: 20.10+ (optional)

### Security Prerequisites

#### Network Security
- **Firewall**: Configured to allow only necessary ports
- **VPN**: Secure access to deployment environment
- **Load Balancer**: For high availability (optional)
- **WAF**: Web Application Firewall (recommended)

#### SSL/TLS Certificates
- **Domain Certificate**: Valid SSL certificate for your domain
- **Certificate Authority**: Trusted CA (Let's Encrypt, DigiCert, etc.)
- **Certificate Renewal**: Automated renewal process

---

## Environment Setup

### 1. System Preparation

#### Update System
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/RHEL
sudo yum update -y
```

#### Install Dependencies
```bash
# Ubuntu/Debian
sudo apt install -y python3 python3-pip python3-venv redis-server postgresql postgresql-contrib nginx certbot python3-certbot-nginx

# CentOS/RHEL
sudo yum install -y python3 python3-pip redis postgresql postgresql-server nginx certbot python3-certbot-nginx
```

#### Create Application User
```bash
# Create secure user for application
sudo useradd -r -s /bin/false secure_llm_proxy
sudo mkdir -p /opt/secure_llm_proxy
sudo chown secure_llm_proxy:secure_llm_proxy /opt/secure_llm_proxy
```

### 2. Python Environment Setup

#### Create Virtual Environment
```bash
cd /opt/secure_llm_proxy
sudo -u secure_llm_proxy python3 -m venv venv
sudo -u secure_llm_proxy venv/bin/pip install --upgrade pip
```

#### Install Application
```bash
# Clone or copy application files
sudo -u secure_llm_proxy git clone <repository_url> .
# OR copy files manually

# Install dependencies
sudo -u secure_llm_proxy venv/bin/pip install -r requirements.txt
```

### 3. Environment Configuration

#### Create Environment File
```bash
sudo -u secure_llm_proxy nano /opt/secure_llm_proxy/.env
```

```env
# Application Configuration
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=postgresql://username:password@localhost/secure_llm_proxy

# Security Configuration
AUTHENTICATION_REQUIRED=true
API_KEY_VALIDATION=true
SSL_VERIFY=true
AUDIT_ENCRYPTION_ENABLED=true
AUDIT_BACKUP_ENABLED=true

# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=your-redis-password

# External Services
LLM_API_KEY=your-llm-api-key
LLM_API_URL=https://api.openai.com/v1

# Monitoring
SENTRY_DSN=your-sentry-dsn
LOG_LEVEL=INFO
```

#### Set Permissions
```bash
sudo chmod 600 /opt/secure_llm_proxy/.env
sudo chown secure_llm_proxy:secure_llm_proxy /opt/secure_llm_proxy/.env
```

---

## Security Configuration

### 1. Firewall Configuration

#### Configure UFW (Ubuntu)
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

#### Configure firewalld (CentOS/RHEL)
```bash
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 2. Security Headers Configuration

#### Update Security Configuration
```python
# In app.py, update SECURITY_CONFIG
SECURITY_CONFIG = {
    # ... existing config ...
    
    # Production Security Settings
    'authentication_required': True,
    'api_key_validation': True,
    'audit_encryption_enabled': True,
    'audit_backup_enabled': True,
    'require_https': True,
    'security_headers_enabled': True,
    'detailed_error_messages': False,
    'log_sensitive_data': False,
    
    # Network Security
    'allowed_ips': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],  # Adjust for your network
    'blocked_ips': [],
    'allowed_user_agents': [],
    'blocked_user_agents': ['curl', 'wget', 'python-requests', 'bot', 'spider'],
    
    # Rate Limiting
    'rate_limit_requests_per_minute': 30,  # More restrictive for production
    'rate_limit_burst_size': 5,
    'max_concurrent_requests': 50,
    
    # SSL/TLS
    'ssl_cert_file': '/etc/ssl/certs/secure_llm_proxy.crt',
    'ssl_key_file': '/etc/ssl/private/secure_llm_proxy.key',
    'ssl_ciphers': 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
    'ssl_protocols': ['TLSv1.2', 'TLSv1.3'],
}
```

### 3. File Permissions

#### Secure File Permissions
```bash
# Application files
sudo chown -R secure_llm_proxy:secure_llm_proxy /opt/secure_llm_proxy
sudo chmod -R 750 /opt/secure_llm_proxy
sudo chmod 640 /opt/secure_llm_proxy/*.py
sudo chmod 600 /opt/secure_llm_proxy/.env

# Log files
sudo mkdir -p /var/log/secure_llm_proxy
sudo chown secure_llm_proxy:secure_llm_proxy /var/log/secure_llm_proxy
sudo chmod 750 /var/log/secure_llm_proxy

# SSL certificates
sudo chmod 644 /etc/ssl/certs/secure_llm_proxy.crt
sudo chmod 600 /etc/ssl/private/secure_llm_proxy.key
```

---

## Authentication Setup

### 1. Database Setup for Authentication

#### Create Database
```sql
-- Connect to PostgreSQL
sudo -u postgres psql

-- Create database and user
CREATE DATABASE secure_llm_proxy;
CREATE USER secure_llm_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE secure_llm_proxy TO secure_llm_user;
\q
```

#### Initialize Database Schema
```bash
# Run database migrations
sudo -u secure_llm_proxy venv/bin/python manage.py db upgrade
```

### 2. User Management

#### Create Admin User
```bash
sudo -u secure_llm_proxy venv/bin/python manage.py create-admin \
    --username admin \
    --email admin@yourcompany.com \
    --password secure_password
```

#### Create API Keys
```bash
sudo -u secure_llm_proxy venv/bin/python manage.py create-api-key \
    --user admin \
    --name "Production API Key" \
    --expires 365
```

### 3. Authentication Configuration

#### Update Authentication Settings
```python
# In authentication.py
AUTH_CONFIG = {
    'session_timeout_minutes': 30,
    'max_failed_attempts': 5,
    'lockout_duration_minutes': 15,
    'password_min_length': 12,
    'password_require_special': True,
    'password_require_numbers': True,
    'password_require_uppercase': True,
    'password_require_lowercase': True,
    'mfa_required': True,
    'mfa_method': 'totp',  # or 'sms', 'email'
}
```

---

## SSL/TLS Configuration

### 1. Certificate Generation

#### Using Let's Encrypt (Recommended)
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Generate certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Test renewal
sudo certbot renew --dry-run
```

#### Using Self-Signed Certificate (Development)
```bash
# Generate self-signed certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/secure_llm_proxy.key \
    -out /etc/ssl/certs/secure_llm_proxy.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"
```

### 2. Nginx Configuration

#### Create Nginx Configuration
```bash
sudo nano /etc/nginx/sites-available/secure_llm_proxy
```

```nginx
# Upstream configuration
upstream secure_llm_proxy {
    server 127.0.0.1:5000;
    keepalive 32;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS configuration
server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
    limit_req zone=api burst=5 nodelay;

    # Proxy configuration
    location / {
        proxy_pass http://secure_llm_proxy;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://secure_llm_proxy;
    }

    # Security endpoint
    location /security/status {
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        proxy_pass http://secure_llm_proxy;
    }
}
```

#### Enable Site
```bash
sudo ln -s /etc/nginx/sites-available/secure_llm_proxy /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Database Setup

### 1. PostgreSQL Configuration

#### Configure PostgreSQL
```bash
sudo nano /etc/postgresql/12/main/postgresql.conf
```

```conf
# Performance settings
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
log_autovacuum_min_duration = 0
log_error_verbosity = verbose
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
```

#### Configure Access
```bash
sudo nano /etc/postgresql/12/main/pg_hba.conf
```

```conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   secure_llm_proxy secure_llm_user                       md5
host    secure_llm_proxy secure_llm_user       127.0.0.1/32    md5
host    secure_llm_proxy secure_llm_user       ::1/128         md5
```

#### Restart PostgreSQL
```bash
sudo systemctl restart postgresql
```

### 2. Redis Configuration

#### Configure Redis
```bash
sudo nano /etc/redis/redis.conf
```

```conf
# Security
requirepass your-redis-password
bind 127.0.0.1
protected-mode yes

# Performance
maxmemory 256mb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
rdbcompression yes
rdbchecksum yes

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
```

#### Restart Redis
```bash
sudo systemctl restart redis
```

---

## Monitoring and Logging

### 1. Logging Configuration

#### Configure Application Logging
```python
# In app.py, update logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'json': {
            'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(timestamp)s %(level)s %(name)s %(message)s'
        }
    },
    'handlers': {
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/secure_llm_proxy/app.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'formatter': 'detailed'
        },
        'json_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/secure_llm_proxy/audit.jsonl',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'json'
        },
        'syslog': {
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',
            'formatter': 'detailed'
        }
    },
    'loggers': {
        'secure_llm_proxy': {
            'handlers': ['file', 'json_file', 'syslog'],
            'level': 'INFO',
            'propagate': False
        }
    }
}
```

### 2. Monitoring Setup

#### Install Monitoring Tools
```bash
# Install Prometheus and Grafana (optional)
sudo apt install prometheus grafana

# Or use cloud monitoring services
# - AWS CloudWatch
# - Google Cloud Monitoring
# - Azure Monitor
```

#### Configure Health Checks
```bash
# Create health check script
sudo nano /opt/secure_llm_proxy/health_check.sh
```

```bash
#!/bin/bash
# Health check script for monitoring

HEALTH_URL="https://your-domain.com/health"
SECURITY_URL="https://your-domain.com/security/status"

# Check application health
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)
if [ $HEALTH_RESPONSE -ne 200 ]; then
    echo "CRITICAL: Application health check failed"
    exit 2
fi

# Check security status
SECURITY_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $SECURITY_URL)
if [ $SECURITY_RESPONSE -ne 200 ]; then
    echo "WARNING: Security status check failed"
    exit 1
fi

echo "OK: All checks passed"
exit 0
```

```bash
sudo chmod +x /opt/secure_llm_proxy/health_check.sh
```

---

## Deployment Options

### 1. Systemd Service Deployment

#### Create Systemd Service
```bash
sudo nano /etc/systemd/system/secure_llm_proxy.service
```

```ini
[Unit]
Description=Secure LLM Proxy
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=secure_llm_proxy
Group=secure_llm_proxy
WorkingDirectory=/opt/secure_llm_proxy
Environment=PATH=/opt/secure_llm_proxy/venv/bin
ExecStart=/opt/secure_llm_proxy/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:5000 --access-logfile /var/log/secure_llm_proxy/gunicorn.log --error-logfile /var/log/secure_llm_proxy/gunicorn_error.log app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secure_llm_proxy

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/secure_llm_proxy /opt/secure_llm_proxy
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

#### Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable secure_llm_proxy
sudo systemctl start secure_llm_proxy
sudo systemctl status secure_llm_proxy
```

### 2. Docker Deployment

#### Create Dockerfile
```dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN useradd -r -s /bin/false secure_llm_proxy

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set permissions
RUN chown -R secure_llm_proxy:secure_llm_proxy /app
USER secure_llm_proxy

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run application
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "app:app"]
```

#### Create Docker Compose
```yaml
version: '3.8'

services:
  secure_llm_proxy:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://secure_llm_user:password@postgres/secure_llm_proxy
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    networks:
      - secure_network

  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: secure_llm_proxy
      POSTGRES_USER: secure_llm_user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - secure_network

  redis:
    image: redis:6-alpine
    command: redis-server --requirepass password
    volumes:
      - redis_data:/data
    networks:
      - secure_network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl
    depends_on:
      - secure_llm_proxy
    networks:
      - secure_network

volumes:
  postgres_data:
  redis_data:

networks:
  secure_network:
    driver: bridge
```

### 3. Kubernetes Deployment

#### Create Kubernetes Configs
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-llm-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-llm-proxy
  template:
    metadata:
      labels:
        app: secure-llm-proxy
    spec:
      containers:
      - name: secure-llm-proxy
        image: your-registry/secure-llm-proxy:latest
        ports:
        - containerPort: 5000
        env:
        - name: FLASK_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: secure-llm-proxy-secrets
              key: database-url
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5
```

---

## Production Checklist

### Pre-Deployment Checklist

#### Security Checklist
- [ ] SSL/TLS certificates installed and valid
- [ ] Firewall configured and tested
- [ ] Security headers implemented
- [ ] Authentication enabled
- [ ] Rate limiting configured
- [ ] Input validation enabled
- [ ] Error messages sanitized
- [ ] Logging configured securely
- [ ] Database security configured
- [ ] Network security implemented

#### Infrastructure Checklist
- [ ] System requirements met
- [ ] Dependencies installed
- [ ] Environment variables configured
- [ ] Database initialized
- [ ] Redis configured
- [ ] Nginx configured
- [ ] SSL certificates installed
- [ ] Monitoring configured
- [ ] Backup procedures in place
- [ ] Disaster recovery plan ready

#### Application Checklist
- [ ] Application deployed
- [ ] Service started and running
- [ ] Health checks passing
- [ ] Security status verified
- [ ] Audit logging working
- [ ] Rate limiting functional
- [ ] Authentication working
- [ ] API endpoints accessible
- [ ] Error handling tested
- [ ] Performance tested

### Post-Deployment Checklist

#### Monitoring Checklist
- [ ] Application logs monitored
- [ ] Security events tracked
- [ ] Performance metrics collected
- [ ] Error rates monitored
- [ ] Rate limit violations tracked
- [ ] Authentication failures logged
- [ ] SSL certificate expiration monitored
- [ ] Database performance monitored
- [ ] Network traffic analyzed
- [ ] Compliance status tracked

#### Maintenance Checklist
- [ ] Regular security updates scheduled
- [ ] SSL certificate renewal automated
- [ ] Database backups automated
- [ ] Log rotation configured
- [ ] Performance monitoring active
- [ ] Security scanning scheduled
- [ ] Compliance audits planned
- [ ] Incident response procedures ready
- [ ] Documentation updated
- [ ] Team training completed

---

## Operational Procedures

### 1. Startup Procedures

#### Application Startup
```bash
# Start all services
sudo systemctl start postgresql
sudo systemctl start redis
sudo systemctl start nginx
sudo systemctl start secure_llm_proxy

# Verify all services are running
sudo systemctl status postgresql redis nginx secure_llm_proxy

# Check application health
curl -k https://your-domain.com/health
```

#### Health Verification
```bash
# Check application logs
sudo journalctl -u secure_llm_proxy -f

# Check nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# Check database connectivity
sudo -u secure_llm_proxy venv/bin/python -c "import psycopg2; print('Database OK')"
```

### 2. Shutdown Procedures

#### Graceful Shutdown
```bash
# Stop application
sudo systemctl stop secure_llm_proxy

# Wait for active connections to complete
sleep 30

# Stop other services
sudo systemctl stop nginx
sudo systemctl stop redis
sudo systemctl stop postgresql
```

### 3. Backup Procedures

#### Database Backup
```bash
#!/bin/bash
# Database backup script

BACKUP_DIR="/backup/database"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/secure_llm_proxy_$DATE.sql"

# Create backup directory
mkdir -p $BACKUP_DIR

# Create database backup
sudo -u postgres pg_dump secure_llm_proxy > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE

# Remove old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

#### Application Backup
```bash
#!/bin/bash
# Application backup script

BACKUP_DIR="/backup/application"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/secure_llm_proxy_$DATE.tar.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Create application backup
tar -czf $BACKUP_FILE /opt/secure_llm_proxy /var/log/secure_llm_proxy

# Remove old backups (keep 30 days)
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Application backup completed: $BACKUP_FILE"
```

### 4. Update Procedures

#### Application Update
```bash
#!/bin/bash
# Application update script

# Stop application
sudo systemctl stop secure_llm_proxy

# Backup current version
sudo cp -r /opt/secure_llm_proxy /opt/secure_llm_proxy.backup.$(date +%Y%m%d_%H%M%S)

# Update application code
cd /opt/secure_llm_proxy
sudo -u secure_llm_proxy git pull origin main

# Update dependencies
sudo -u secure_llm_proxy venv/bin/pip install -r requirements.txt

# Run database migrations
sudo -u secure_llm_proxy venv/bin/python manage.py db upgrade

# Start application
sudo systemctl start secure_llm_proxy

# Verify health
sleep 10
curl -k https://your-domain.com/health

echo "Application update completed"
```

### 5. Monitoring Procedures

#### Daily Monitoring
```bash
#!/bin/bash
# Daily monitoring script

# Check application health
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/health)
if [ $HEALTH -ne 200 ]; then
    echo "CRITICAL: Application health check failed"
    # Send alert
fi

# Check disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "WARNING: Disk usage is $DISK_USAGE%"
    # Send alert
fi

# Check log file sizes
LOG_SIZE=$(du -m /var/log/secure_llm_proxy/ | awk '{print $1}')
if [ $LOG_SIZE -gt 1000 ]; then
    echo "WARNING: Log files are $LOG_SIZE MB"
    # Rotate logs
fi

echo "Daily monitoring completed"
```

---

## Troubleshooting

### 1. Common Issues

#### Application Won't Start
```bash
# Check service status
sudo systemctl status secure_llm_proxy

# Check logs
sudo journalctl -u secure_llm_proxy -n 50

# Check permissions
ls -la /opt/secure_llm_proxy/
ls -la /var/log/secure_llm_proxy/

# Check environment
sudo -u secure_llm_proxy cat /opt/secure_llm_proxy/.env
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check database connectivity
sudo -u postgres psql -d secure_llm_proxy -c "SELECT 1;"

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-12-main.log
```

#### SSL Certificate Issues
```bash
# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/your-domain.com/cert.pem -text -noout

# Check certificate expiration
openssl x509 -in /etc/letsencrypt/live/your-domain.com/cert.pem -noout -dates

# Renew certificate
sudo certbot renew
```

### 2. Performance Issues

#### High CPU Usage
```bash
# Check process usage
top -p $(pgrep -f secure_llm_proxy)

# Check system resources
htop

# Check application metrics
curl -s https://your-domain.com/security/status | jq '.security_metrics'
```

#### High Memory Usage
```bash
# Check memory usage
free -h

# Check Redis memory
redis-cli info memory

# Check PostgreSQL memory
sudo -u postgres psql -c "SELECT * FROM pg_stat_bgwriter;"
```

### 3. Security Issues

#### Rate Limit Violations
```bash
# Check rate limit logs
grep "RATE_LIMIT_EXCEEDED" /var/log/secure_llm_proxy/app.log

# Check Redis rate limiting
redis-cli keys "*rate_limit*"

# Adjust rate limits if needed
# Update SECURITY_CONFIG in app.py
```

#### Authentication Failures
```bash
# Check authentication logs
grep "AUTHENTICATION_FAILED" /var/log/secure_llm_proxy/app.log

# Check user accounts
sudo -u secure_llm_proxy venv/bin/python manage.py list-users

# Reset user password if needed
sudo -u secure_llm_proxy venv/bin/python manage.py reset-password --username admin
```

### 4. Log Analysis

#### Security Event Analysis
```bash
# Search for security events
grep "SECURITY_EVENT" /var/log/secure_llm_proxy/audit.jsonl | jq '.'

# Analyze rate limit violations
grep "RATE_LIMIT" /var/log/secure_llm_proxy/app.log | wc -l

# Check for suspicious IPs
grep "BLOCKED_IP" /var/log/secure_llm_proxy/app.log | awk '{print $NF}' | sort | uniq -c
```

#### Performance Analysis
```bash
# Analyze response times
grep "PROCESSING_TIME" /var/log/secure_llm_proxy/app.log | awk '{print $NF}' | sort -n

# Check error rates
grep "ERROR" /var/log/secure_llm_proxy/app.log | wc -l

# Analyze API usage
grep "POST /chat" /var/log/nginx/access.log | wc -l
```

---

## Support and Maintenance

### 1. Regular Maintenance

#### Weekly Tasks
- [ ] Review security logs
- [ ] Check SSL certificate status
- [ ] Monitor disk space usage
- [ ] Review performance metrics
- [ ] Update security patches

#### Monthly Tasks
- [ ] Review audit reports
- [ ] Update application dependencies
- [ ] Review and rotate API keys
- [ ] Conduct security assessments
- [ ] Update documentation

#### Quarterly Tasks
- [ ] Conduct penetration testing
- [ ] Review compliance status
- [ ] Update security policies
- [ ] Conduct disaster recovery testing
- [ ] Review and update procedures

### 2. Emergency Procedures

#### Security Incident Response
1. **Identify**: Determine the nature and scope of the incident
2. **Contain**: Isolate affected systems and prevent further damage
3. **Eradicate**: Remove the threat and restore system integrity
4. **Recover**: Restore normal operations
5. **Learn**: Document lessons learned and improve procedures

#### System Failure Response
1. **Assess**: Determine the cause and impact of the failure
2. **Communicate**: Notify stakeholders and users
3. **Mitigate**: Implement temporary workarounds
4. **Restore**: Restore system functionality
5. **Validate**: Verify system is working correctly

---

**Version**: 1.0  
**Last Updated**: 2024  
**Security Level**: Production-Ready  
**Compliance Status**: Multi-Framework Ready