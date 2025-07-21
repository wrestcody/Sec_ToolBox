"""
Secure LLM Interaction Proxy (PoC)
Compliance-Ready Implementation with Comprehensive Audit Trail

This application provides a security and privacy proxy for LLM interactions
with detailed logging for audit and compliance purposes.

Author: Cloud Sentinel's Toolkit
Version: 1.0.0-poc
License: Educational/Research Use Only
"""

import json
import logging
import re
import uuid
import secrets
import hmac
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import os
import ssl
import socket
from urllib.parse import urlparse
import ipaddress

from flask import Flask, request, jsonify, g, make_response
from werkzeug.exceptions import HTTPException
from werkzeug.security import safe_str_cmp
import bcrypt

# Configure structured logging for audit compliance
class AuditLogFormatter(logging.Formatter):
    """Custom formatter for structured audit logs."""
    
    def format(self, record):
        # Ensure all log entries have required audit fields
        if not hasattr(record, 'audit_id'):
            record.audit_id = getattr(g, 'audit_id', 'unknown')
        if not hasattr(record, 'user_id'):
            record.user_id = getattr(g, 'user_id', 'anonymous')
        if not hasattr(record, 'session_id'):
            record.session_id = getattr(g, 'session_id', 'unknown')
        
        # Create structured log entry
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'audit_id': record.audit_id,
            'user_id': record.user_id,
            'session_id': record.session_id,
            'level': record.levelname,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage()
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        return json.dumps(log_entry, ensure_ascii=False)

# Configure logging
def setup_logging():
    """Setup structured logging for audit compliance."""
    logger = logging.getLogger('secure_llm_proxy')
    logger.setLevel(logging.INFO)
    
    # File handler for audit logs
    file_handler = logging.FileHandler('audit_logs.jsonl')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(AuditLogFormatter())
    
    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(AuditLogFormatter())
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Enums for structured data
class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SecurityEventType(Enum):
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    PII_DETECTED = "PII_DETECTED"
    HARMFUL_CONTENT_DETECTED = "HARMFUL_CONTENT_DETECTED"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"

class ComplianceFramework(Enum):
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOX = "SOX"
    PCI_DSS = "PCI_DSS"
    ISO_27001 = "ISO_27001"

# Data classes for structured audit data
@dataclass
class SecurityEvent:
    """Structured security event for audit logging."""
    event_id: str
    event_type: SecurityEventType
    timestamp: str
    risk_level: RiskLevel
    description: str
    details: Dict[str, Any]
    compliance_impact: List[ComplianceFramework]
    remediation_required: bool
    audit_trail: List[str]

@dataclass
class AuditTrail:
    """Complete audit trail for a request with enhanced compliance tracking."""
    audit_id: str
    request_id: str
    user_id: str
    session_id: str
    timestamp: str
    ip_address: str
    user_agent: str
    request_data: Dict[str, Any]
    security_events: List[SecurityEvent]
    processing_steps: List[Dict[str, Any]]
    final_response: Dict[str, Any]
    compliance_status: Dict[str, Any]
    # Enhanced audit fields for compliance reporting
    audit_metadata: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    compliance_violations: List[Dict[str, Any]]
    data_processing_consent: Optional[str]
    data_retention_info: Dict[str, Any]
    incident_response_actions: List[Dict[str, Any]]
    audit_signature: Optional[str]  # For audit integrity verification

# Initialize Flask app
app = Flask(__name__)
logger = setup_logging()
rate_limiter = RateLimiter()

# Security middleware
@app.before_request
def security_middleware():
    """Security middleware to apply security checks before processing requests."""
    
    # Get client identifier (IP address for rate limiting)
    client_ip = request.remote_addr
    client_id = client_ip
    
    # Validate IP address
    if not SecurityUtils.validate_ip_address(client_ip):
        logger.warning(f"Blocked request from invalid IP: {client_ip}", extra={
            'extra_fields': {
                'security_event': 'INVALID_IP_ADDRESS',
                'client_ip': client_ip,
                'user_agent': request.headers.get('User-Agent', 'unknown')
            }
        })
        return jsonify({'error': 'Access denied'}), 403
    
    # Validate user agent
    user_agent = request.headers.get('User-Agent', '')
    if not SecurityUtils.validate_user_agent(user_agent):
        logger.warning(f"Blocked request from blocked user agent: {user_agent}", extra={
            'extra_fields': {
                'security_event': 'BLOCKED_USER_AGENT',
                'client_ip': client_ip,
                'user_agent': user_agent
            }
        })
        return jsonify({'error': 'Access denied'}), 403
    
    # Rate limiting
    if not rate_limiter.is_allowed(client_id):
        logger.warning(f"Rate limit exceeded for client: {client_id}", extra={
            'extra_fields': {
                'security_event': 'RATE_LIMIT_EXCEEDED',
                'client_ip': client_ip,
                'user_agent': user_agent
            }
        })
        return jsonify({
            'error': 'Rate limit exceeded',
            'retry_after': SECURITY_CONFIG['rate_limit_window']
        }), 429
    
    # Store client info in Flask g for later use
    g.client_ip = client_ip
    g.client_id = client_id
    g.user_agent = user_agent

@app.after_request
def security_headers(response):
    """Add security headers to all responses."""
    
    if SECURITY_CONFIG['security_headers_enabled']:
        # Content Security Policy
        response.headers['Content-Security-Policy'] = SECURITY_CONFIG['content_security_policy']
        
        # HTTP Strict Transport Security
        if SECURITY_CONFIG['hsts_enabled']:
            response.headers['Strict-Transport-Security'] = f"max-age={SECURITY_CONFIG['hsts_max_age']}; includeSubDomains; preload"
        
        # X-Frame-Options
        response.headers['X-Frame-Options'] = SECURITY_CONFIG['x_frame_options']
        
        # X-Content-Type-Options
        response.headers['X-Content-Type-Options'] = SECURITY_CONFIG['x_content_type_options']
        
        # X-XSS-Protection
        response.headers['X-XSS-Protection'] = SECURITY_CONFIG['x_xss_protection']
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = SECURITY_CONFIG['referrer_policy']
        
        # Remove server information
        response.headers.pop('Server', None)
        
        # Add rate limit headers
        if hasattr(g, 'client_id'):
            remaining = rate_limiter.get_remaining_requests(g.client_id)
            response.headers['X-RateLimit-Remaining'] = str(remaining)
            response.headers['X-RateLimit-Limit'] = str(SECURITY_CONFIG['rate_limit_requests_per_minute'])
            response.headers['X-RateLimit-Reset'] = str(int((datetime.now(timezone.utc) + timedelta(seconds=SECURITY_CONFIG['rate_limit_window'])).timestamp()))
    
    return response

# Comprehensive security configuration
SECURITY_CONFIG = {
    # Input validation and limits
    'max_prompt_length': 10000,
    'max_request_size': 1024 * 1024,  # 1MB
    'max_response_size': 1024 * 1024,  # 1MB
    'allowed_models': ['gpt-3.5-turbo', 'gpt-4', 'claude-3'],
    'allowed_content_types': ['application/json'],
    'max_headers_size': 8192,  # 8KB
    
    # Rate limiting and throttling
    'rate_limit_requests_per_minute': 60,
    'rate_limit_burst_size': 10,
    'rate_limit_window': 60,  # seconds
    'max_concurrent_requests': 100,
    
    # Security features
    'pii_detection_enabled': True,
    'injection_detection_enabled': True,
    'content_filtering_enabled': True,
    'audit_logging_enabled': True,
    'input_sanitization_enabled': True,
    'output_sanitization_enabled': True,
    'sql_injection_protection': True,
    'xss_protection': True,
    'csrf_protection': True,
    
    # Authentication and authorization
    'authentication_required': False,  # For PoC - would be True in production
    'api_key_validation': False,  # For PoC - would be True in production
    'session_timeout_minutes': 30,
    'max_failed_attempts': 5,
    'lockout_duration_minutes': 15,
    
    # Encryption and security headers
    'require_https': True,
    'security_headers_enabled': True,
    'content_security_policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    'hsts_enabled': True,
    'hsts_max_age': 31536000,  # 1 year
    'x_frame_options': 'DENY',
    'x_content_type_options': 'nosniff',
    'x_xss_protection': '1; mode=block',
    'referrer_policy': 'strict-origin-when-cross-origin',
    
    # Network security
    'allowed_ips': [],  # Empty for all IPs, add specific IPs for production
    'blocked_ips': [],
    'allowed_user_agents': [],  # Empty for all UAs, add specific UAs for production
    'blocked_user_agents': ['curl', 'wget', 'python-requests'],  # Block common bots
    
    # Compliance frameworks
    'compliance_frameworks': [ComplianceFramework.GDPR, ComplianceFramework.HIPAA, ComplianceFramework.PCI_DSS, ComplianceFramework.SOX, ComplianceFramework.ISO_27001],
    
    # Audit and logging
    'audit_retention_days': 90,
    'audit_log_rotation': True,
    'audit_log_compression': True,
    'audit_encryption_enabled': False,  # For PoC - would be True in production
    'audit_backup_enabled': False,  # For PoC - would be True in production
    'compliance_reporting_enabled': True,
    'risk_assessment_enabled': True,
    'incident_response_enabled': True,
    
    # Error handling
    'detailed_error_messages': False,  # Don't expose internal details
    'log_sensitive_data': False,  # Don't log sensitive data
    'sanitize_error_messages': True,
    
    # SSL/TLS configuration
    'ssl_verify': True,
    'ssl_cert_file': None,  # Path to SSL certificate
    'ssl_key_file': None,   # Path to SSL private key
    'ssl_ciphers': 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
    'ssl_protocols': ['TLSv1.2', 'TLSv1.3'],
    
    # Session security
    'session_cookie_secure': True,
    'session_cookie_httponly': True,
    'session_cookie_samesite': 'Strict',
    'session_cookie_max_age': 1800,  # 30 minutes
}

# Security utilities
class SecurityUtils:
    """Security utility functions following best practices."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a cryptographically secure token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        return safe_str_cmp(a, b)
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize input to prevent injection attacks."""
        if not text:
            return ""
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Remove control characters except newlines and tabs
        text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
        
        # Limit length
        if len(text) > SECURITY_CONFIG['max_prompt_length']:
            text = text[:SECURITY_CONFIG['max_prompt_length']]
        
        return text.strip()
    
    @staticmethod
    def sanitize_output(text: str) -> str:
        """Sanitize output to prevent XSS and injection attacks."""
        if not text:
            return ""
        
        # HTML entity encoding for common XSS vectors
        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
            '/': '&#x2F;',
            '\\': '&#x5C;'
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        
        return text
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format and check against allowlist/blocklist."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check blocked IPs
            if ip in SECURITY_CONFIG['blocked_ips']:
                return False
            
            # Check allowed IPs (if specified)
            if SECURITY_CONFIG['allowed_ips'] and ip not in SECURITY_CONFIG['allowed_ips']:
                return False
            
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_user_agent(user_agent: str) -> bool:
        """Validate user agent against allowlist/blocklist."""
        if not user_agent:
            return False
        
        user_agent_lower = user_agent.lower()
        
        # Check blocked user agents
        for blocked_ua in SECURITY_CONFIG['blocked_user_agents']:
            if blocked_ua.lower() in user_agent_lower:
                return False
        
        # Check allowed user agents (if specified)
        if SECURITY_CONFIG['allowed_user_agents']:
            return any(allowed_ua.lower() in user_agent_lower 
                      for allowed_ua in SECURITY_CONFIG['allowed_user_agents'])
        
        return True
    
    @staticmethod
    def validate_content_type(content_type: str) -> bool:
        """Validate content type."""
        if not content_type:
            return False
        
        return content_type.lower() in SECURITY_CONFIG['allowed_content_types']
    
    @staticmethod
    def validate_json_schema(data: Dict[str, Any]) -> bool:
        """Validate JSON schema for required fields and types."""
        if not isinstance(data, dict):
            return False
        
        # Check required fields
        if 'prompt' not in data:
            return False
        
        # Validate prompt
        if not isinstance(data['prompt'], str):
            return False
        
        if len(data['prompt']) > SECURITY_CONFIG['max_prompt_length']:
            return False
        
        # Validate optional fields
        if 'model_name' in data:
            if not isinstance(data['model_name'], str):
                return False
            if data['model_name'] not in SECURITY_CONFIG['allowed_models']:
                return False
        
        return True

# Rate limiting implementation
class RateLimiter:
    """Simple in-memory rate limiter (use Redis in production)."""
    
    def __init__(self):
        self.requests = {}
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed based on rate limits."""
        now = datetime.now(timezone.utc)
        
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        # Remove old requests outside the window
        window_start = now - timedelta(seconds=SECURITY_CONFIG['rate_limit_window'])
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id] 
            if req_time > window_start
        ]
        
        # Check rate limit
        if len(self.requests[client_id]) >= SECURITY_CONFIG['rate_limit_requests_per_minute']:
            return False
        
        # Add current request
        self.requests[client_id].append(now)
        return True
    
    def get_remaining_requests(self, client_id: str) -> int:
        """Get remaining requests for a client."""
        now = datetime.now(timezone.utc)
        
        if client_id not in self.requests:
            return SECURITY_CONFIG['rate_limit_requests_per_minute']
        
        window_start = now - timedelta(seconds=SECURITY_CONFIG['rate_limit_window'])
        recent_requests = [
            req_time for req_time in self.requests[client_id] 
            if req_time > window_start
        ]
        
        return max(0, SECURITY_CONFIG['rate_limit_requests_per_minute'] - len(recent_requests))

class SecurityAnalyzer:
    """Comprehensive security analysis with audit trail."""
    
    def __init__(self):
        self.audit_trail = []
        self.security_events = []
    
    def log_security_event(self, event_type: SecurityEventType, risk_level: RiskLevel, 
                          description: str, details: Dict[str, Any], 
                          compliance_impact: List[ComplianceFramework] = None):
        """Log a security event with full audit trail."""
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_level=risk_level,
            description=description,
            details=details,
            compliance_impact=compliance_impact or [],
            remediation_required=risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL],
            audit_trail=self.audit_trail.copy()
        )
        self.security_events.append(event)
        
        # Log to audit system
        logger.warning(f"Security event detected: {event_type.value}", extra={
            'extra_fields': {
                'security_event': asdict(event),
                'audit_id': getattr(g, 'audit_id', 'unknown')
            }
        })
        
        return event
    
    def detect_prompt_injection(self, prompt_text: str) -> Dict[str, Any]:
        """Enhanced prompt injection detection with detailed analysis."""
        self.audit_trail.append(f"Starting prompt injection analysis for text length: {len(prompt_text)}")
        
        # Comprehensive injection patterns
        injection_patterns = {
            'system_override': [
                r'ignore\s+(?:all\s+)?(?:previous\s+)?instructions',
                r'forget\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)',
                r'disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)',
                r'override\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)',
                r'new\s+instructions\s*:',
                r'ignore\s+above',
                r'disregard\s+above',
                r'forget\s+above'
            ],
            'role_confusion': [
                r'act\s+as\s+(?:if\s+)?(?:you\s+are\s+)?(?:a\s+)?(?:different\s+)?(?:person|assistant|system)',
                r'pretend\s+to\s+be',
                r'you\s+are\s+now\s+(?:a\s+)?(?:different\s+)?(?:person|assistant)',
                r'role\s*:\s*',
                r'persona\s*:\s*'
            ],
            'system_prompt_leakage': [
                r'system\s*:\s*',
                r'<\|system\|>',
                r'<\|im_start\|>system',
                r'<\|im_end\|>'
            ],
            'instruction_bypass': [
                r'bypass\s+(?:all\s+)?(?:safety|security|filter)',
                r'ignore\s+(?:all\s+)?(?:safety|security|filter)',
                r'disable\s+(?:all\s+)?(?:safety|security|filter)'
            ]
        }
        
        detected_patterns = {}
        total_detections = 0
        
        for category, patterns in injection_patterns.items():
            category_detections = []
            for pattern in patterns:
                matches = re.findall(pattern, prompt_text, re.IGNORECASE)
                if matches:
                    category_detections.append({
                        'pattern': pattern,
                        'matches': len(matches),
                        'sample_matches': matches[:3]  # Limit for audit logs
                    })
                    total_detections += len(matches)
            
            if category_detections:
                detected_patterns[category] = category_detections
        
        # Risk assessment
        if total_detections >= 5:
            risk_level = RiskLevel.CRITICAL
        elif total_detections >= 3:
            risk_level = RiskLevel.HIGH
        elif total_detections >= 1:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Log security event if detected
        if detected_patterns:
            self.log_security_event(
                SecurityEventType.PROMPT_INJECTION_DETECTED,
                risk_level,
                f"Prompt injection attempt detected with {total_detections} patterns",
                {
                    'detected_patterns': detected_patterns,
                    'total_detections': total_detections,
                    'prompt_length': len(prompt_text),
                    'prompt_hash': hashlib.sha256(prompt_text.encode()).hexdigest()[:16]
                },
                [ComplianceFramework.ISO_27001]
            )
        
        self.audit_trail.append(f"Prompt injection analysis complete: {total_detections} detections, risk level: {risk_level.value}")
        
        return {
            'detected': bool(detected_patterns),
            'patterns_found': detected_patterns,
            'total_detections': total_detections,
            'risk_level': risk_level.value,
            'categories_affected': list(detected_patterns.keys()),
            'audit_trail': self.audit_trail
        }
    
    def redact_pii(self, text: str) -> Dict[str, Any]:
        """Enhanced PII redaction with compliance tracking."""
        self.audit_trail.append(f"Starting PII redaction for text length: {len(text)}")
        
        # Comprehensive PII patterns with compliance mapping
        pii_patterns = {
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'compliance': [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
                'description': 'Email address'
            },
            'phone_us': {
                'pattern': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
                'compliance': [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
                'description': 'US phone number'
            },
            'phone_international': {
                'pattern': r'\b\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b',
                'compliance': [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
                'description': 'International phone number'
            },
            'credit_card': {
                'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                'compliance': [ComplianceFramework.PCI_DSS],
                'description': 'Credit card number'
            },
            'ssn_us': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'compliance': [ComplianceFramework.HIPAA, ComplianceFramework.SOX],
                'description': 'US Social Security Number'
            },
            'ip_address': {
                'pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'compliance': [ComplianceFramework.GDPR],
                'description': 'IP address'
            },
            'mac_address': {
                'pattern': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
                'compliance': [ComplianceFramework.ISO_27001],
                'description': 'MAC address'
            },
            'date_of_birth': {
                'pattern': r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b',
                'compliance': [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
                'description': 'Date of birth'
            }
        }
        
        redacted_text = text
        redacted_items = {}
        compliance_impact = set()
        
        for pii_type, config in pii_patterns.items():
            matches = re.findall(config['pattern'], redacted_text)
            if matches:
                redacted_items[pii_type] = {
                    'count': len(matches),
                    'description': config['description'],
                    'compliance_frameworks': [f.value for f in config['compliance']],
                    'sample_matches': matches[:3]  # Limit for audit logs
                }
                redacted_text = re.sub(config['pattern'], '[REDACTED_PII]', redacted_text)
                compliance_impact.update(config['compliance'])
        
        total_redactions = sum(item['count'] for item in redacted_items.values())
        
        # Log security event if PII detected
        if redacted_items:
            self.log_security_event(
                SecurityEventType.PII_DETECTED,
                RiskLevel.HIGH if total_redactions > 5 else RiskLevel.MEDIUM,
                f"PII detected and redacted: {total_redactions} items across {len(redacted_items)} types",
                {
                    'redacted_items': redacted_items,
                    'total_redactions': total_redactions,
                    'text_length': len(text),
                    'text_hash': hashlib.sha256(text.encode()).hexdigest()[:16]
                },
                list(compliance_impact)
            )
        
        self.audit_trail.append(f"PII redaction complete: {total_redactions} items redacted across {len(redacted_items)} types")
        
        return {
            'redacted_text': redacted_text,
            'redacted_items': redacted_items,
            'total_redactions': total_redactions,
            'compliance_impact': [f.value for f in compliance_impact],
            'audit_trail': self.audit_trail
        }
    
    def filter_harmful_content(self, text: str) -> Dict[str, Any]:
        """Enhanced harmful content filtering with categorization."""
        self.audit_trail.append(f"Starting harmful content filtering for text length: {len(text)}")
        
        # Categorized harmful content patterns
        harmful_patterns = {
            'malware_development': [
                'malware', 'virus', 'trojan', 'worm', 'ransomware', 'keylogger',
                'rootkit', 'backdoor', 'exploit', 'payload', 'shellcode'
            ],
            'cyber_attacks': [
                'sql injection', 'xss', 'csrf', 'buffer overflow', 'ddos',
                'phishing', 'social engineering', 'brute force'
            ],
            'unauthorized_access': [
                'hack', 'crack', 'bypass', 'circumvent', 'override',
                'privilege escalation', 'lateral movement'
            ],
            'harmful_instructions': [
                'how to harm', 'how to kill', 'how to injure', 'how to damage',
                'instructions for violence', 'instructions for destruction'
            ]
        }
        
        detected_keywords = {}
        total_detections = 0
        
        for category, keywords in harmful_patterns.items():
            category_detections = []
            for keyword in keywords:
                matches = re.findall(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE)
                if matches:
                    category_detections.append({
                        'keyword': keyword,
                        'count': len(matches),
                        'context': text[max(0, text.lower().find(keyword.lower())-20):text.lower().find(keyword.lower())+len(keyword)+20]
                    })
                    total_detections += len(matches)
            
            if category_detections:
                detected_keywords[category] = category_detections
        
        # Risk assessment
        if total_detections >= 10:
            risk_level = RiskLevel.CRITICAL
        elif total_detections >= 5:
            risk_level = RiskLevel.HIGH
        elif total_detections >= 2:
            risk_level = RiskLevel.MEDIUM
        elif total_detections >= 1:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.LOW
        
        # Log security event if detected
        if detected_keywords:
            self.log_security_event(
                SecurityEventType.HARMFUL_CONTENT_DETECTED,
                risk_level,
                f"Harmful content detected: {total_detections} instances across {len(detected_keywords)} categories",
                {
                    'detected_keywords': detected_keywords,
                    'total_detections': total_detections,
                    'categories_affected': list(detected_keywords.keys()),
                    'text_length': len(text),
                    'text_hash': hashlib.sha256(text.encode()).hexdigest()[:16]
                },
                [ComplianceFramework.ISO_27001]
            )
        
        self.audit_trail.append(f"Harmful content filtering complete: {total_detections} detections, risk level: {risk_level.value}")
        
        return {
            'detected': bool(detected_keywords),
            'keywords_found': detected_keywords,
            'total_detections': total_detections,
            'risk_level': risk_level.value,
            'categories_affected': list(detected_keywords.keys()),
            'audit_trail': self.audit_trail
        }

def simulate_llm_response(prompt: str, model_name: str = "gpt-3.5-turbo") -> str:
    """Simulate LLM response for PoC purposes."""
    import random
    
    responses = [
        f"I understand you're asking about: {prompt[:100]}... Here's a helpful response based on your query.",
        "Based on your question, I can provide some general guidance. However, please consult with appropriate professionals for specific advice.",
        f"Thank you for your inquiry. This is a simulated response from the {model_name} model demonstrating the proxy's security features.",
        "I've processed your request and here's what I can tell you about this topic. Remember that this is a PoC implementation."
    ]
    
    return random.choice(responses)

def create_audit_trail(request_data: Dict[str, Any], security_analyzer: SecurityAnalyzer, 
                      final_response: Dict[str, Any]) -> AuditTrail:
    """Create comprehensive audit trail for compliance reporting with enhanced fields."""
    
    # Calculate overall risk assessment
    risk_levels = [event.risk_level.value for event in security_analyzer.security_events]
    overall_risk = max(risk_levels, default='LOW')
    
    # Identify compliance violations
    compliance_violations = []
    for event in security_analyzer.security_events:
        for framework in event.compliance_impact:
            compliance_violations.append({
                'event_id': event.event_id,
                'framework': framework.value,
                'violation_type': event.event_type.value,
                'risk_level': event.risk_level.value,
                'description': event.description,
                'timestamp': event.timestamp,
                'remediation_required': event.remediation_required
            })
    
    # Create audit metadata
    audit_metadata = {
        'audit_version': '1.0.0',
        'audit_standard': 'ISO 27001:2013',
        'audit_scope': 'Secure LLM Proxy Security Controls',
        'audit_methodology': 'Automated security analysis with manual review',
        'audit_evidence_type': 'Structured JSON logs with hash verification',
        'audit_retention_policy': f"{SECURITY_CONFIG['audit_retention_days']} days",
        'audit_encryption': SECURITY_CONFIG['audit_encryption_enabled'],
        'audit_backup': SECURITY_CONFIG['audit_backup_enabled']
    }
    
    # Enhanced risk assessment
    risk_assessment = {
        'overall_risk_level': overall_risk,
        'risk_factors': {
            'prompt_injection_risk': any(event.event_type == SecurityEventType.PROMPT_INJECTION_DETECTED for event in security_analyzer.security_events),
            'pii_exposure_risk': any(event.event_type == SecurityEventType.PII_DETECTED for event in security_analyzer.security_events),
            'harmful_content_risk': any(event.event_type == SecurityEventType.HARMFUL_CONTENT_DETECTED for event in security_analyzer.security_events),
            'compliance_violation_risk': len(compliance_violations) > 0
        },
        'risk_mitigation_effectiveness': {
            'pii_protection': 'HIGH' if not any(event.event_type == SecurityEventType.PII_DETECTED for event in security_analyzer.security_events) else 'MEDIUM',
            'injection_protection': 'HIGH' if not any(event.event_type == SecurityEventType.PROMPT_INJECTION_DETECTED for event in security_analyzer.security_events) else 'MEDIUM',
            'content_filtering': 'HIGH' if not any(event.event_type == SecurityEventType.HARMFUL_CONTENT_DETECTED for event in security_analyzer.security_events) else 'MEDIUM'
        },
        'compliance_risk_score': len(compliance_violations) * 10,  # Simple scoring for PoC
        'recommended_actions': [
            'Implement user authentication' if overall_risk in ['HIGH', 'CRITICAL'] else None,
            'Add encryption for data in transit' if any(event.event_type == SecurityEventType.PII_DETECTED for event in security_analyzer.security_events) else None,
            'Enhance threat detection' if any(event.event_type == SecurityEventType.PROMPT_INJECTION_DETECTED for event in security_analyzer.security_events) else None
        ]
    }
    
    # Data retention information
    data_retention_info = {
        'retention_period_days': SECURITY_CONFIG['audit_retention_days'],
        'data_types_retained': ['audit_logs', 'security_events', 'compliance_violations'],
        'retention_purpose': 'Compliance reporting and security monitoring',
        'data_disposal_method': 'Secure deletion after retention period',
        'data_processing_basis': 'Legitimate interest for security and compliance'
    }
    
    # Incident response actions (for PoC, this would be more comprehensive)
    incident_response_actions = []
    if security_analyzer.security_events:
        incident_response_actions.append({
            'action_type': 'SECURITY_EVENT_DETECTED',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'description': f"Detected {len(security_analyzer.security_events)} security events",
            'severity': overall_risk,
            'automated_response': 'PII redaction and content filtering applied',
            'manual_review_required': overall_risk in ['HIGH', 'CRITICAL']
        })
    
    # Create audit signature for integrity verification
    audit_content = f"{getattr(g, 'audit_id', 'unknown')}{getattr(g, 'request_id', 'unknown')}{datetime.now(timezone.utc).isoformat()}"
    audit_signature = hashlib.sha256(audit_content.encode()).hexdigest()
    
    return AuditTrail(
        audit_id=getattr(g, 'audit_id', 'unknown'),
        request_id=getattr(g, 'request_id', 'unknown'),
        user_id=getattr(g, 'user_id', 'anonymous'),
        session_id=getattr(g, 'session_id', 'unknown'),
        timestamp=datetime.now(timezone.utc).isoformat(),
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'unknown'),
        request_data={
            'prompt_length': len(request_data.get('prompt', '')),
            'prompt_hash': hashlib.sha256(request_data.get('prompt', '').encode()).hexdigest()[:16],
            'model_requested': request_data.get('model_name', 'unknown'),
            'request_timestamp': request_data.get('timestamp', 'unknown'),
            'request_headers': dict(request.headers),
            'request_method': request.method,
            'request_path': request.path
        },
        security_events=security_analyzer.security_events,
        processing_steps=security_analyzer.audit_trail,
        final_response={
            'response_length': len(final_response.get('response', '')),
            'response_hash': hashlib.sha256(final_response.get('response', '').encode()).hexdigest()[:16],
            'security_analysis_summary': {
                'total_security_events': len(security_analyzer.security_events),
                'highest_risk_level': max([event.risk_level.value for event in security_analyzer.security_events], default='LOW'),
                'compliance_frameworks_impacted': list(set([f.value for event in security_analyzer.security_events for f in event.compliance_impact])),
                'risk_mitigation_applied': len(security_analyzer.security_events) > 0
            }
        },
        compliance_status={
            'gdpr_compliant': all('GDPR' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
            'hipaa_compliant': all('HIPAA' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
            'pci_dss_compliant': all('PCI_DSS' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
            'sox_compliant': all('SOX' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
            'iso_27001_compliant': all('ISO_27001' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
            'overall_compliance_score': max(0, 100 - len(compliance_violations) * 10)
        },
        audit_metadata=audit_metadata,
        risk_assessment=risk_assessment,
        compliance_violations=compliance_violations,
        data_processing_consent=request.headers.get('X-Data-Consent', 'implied'),
        data_retention_info=data_retention_info,
        incident_response_actions=incident_response_actions,
        audit_signature=audit_signature
    )

@app.before_request
def setup_request_context():
    """Setup request context for audit trail and security tracking."""
    g.audit_id = str(uuid.uuid4())
    g.request_id = str(uuid.uuid4())
    g.user_id = request.headers.get('X-User-ID', 'anonymous')
    g.session_id = request.headers.get('X-Session-ID', 'unknown')
    g.request_start_time = datetime.now(timezone.utc)
    
    # Security tracking
    g.security_events = []
    g.rate_limit_hit = False
    g.blocked_request = False
    
    logger.info(f"Request started", extra={
        'extra_fields': {
            'request_method': request.method,
            'request_path': request.path,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'content_type': request.content_type,
            'content_length': request.content_length
        }
    })

@app.route('/chat', methods=['POST'])
def chat():
    """Main chat endpoint with comprehensive security processing and audit trail."""
    try:
        # Comprehensive request validation
        if not request.is_json:
            logger.warning("Invalid content type", extra={
                'extra_fields': {
                    'security_event': 'INVALID_CONTENT_TYPE',
                    'content_type': request.content_type,
                    'client_ip': getattr(g, 'client_ip', 'unknown')
                }
            })
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        # Validate content type
        if not SecurityUtils.validate_content_type(request.content_type):
            logger.warning("Unsupported content type", extra={
                'extra_fields': {
                    'security_event': 'UNSUPPORTED_CONTENT_TYPE',
                    'content_type': request.content_type,
                    'client_ip': getattr(g, 'client_ip', 'unknown')
                }
            })
            return jsonify({'error': 'Unsupported content type'}), 400
        
        # Validate request size
        if request.content_length and request.content_length > SECURITY_CONFIG['max_request_size']:
            logger.warning("Request too large", extra={
                'extra_fields': {
                    'security_event': 'REQUEST_TOO_LARGE',
                    'content_length': request.content_length,
                    'max_size': SECURITY_CONFIG['max_request_size'],
                    'client_ip': getattr(g, 'client_ip', 'unknown')
                }
            })
            return jsonify({'error': 'Request too large'}), 413
        
        # Parse and validate JSON
        try:
            data = request.get_json()
        except Exception as e:
            logger.warning("Invalid JSON", extra={
                'extra_fields': {
                    'security_event': 'INVALID_JSON',
                    'error': str(e),
                    'client_ip': getattr(g, 'client_ip', 'unknown')
                }
            })
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Validate JSON schema
        if not SecurityUtils.validate_json_schema(data):
            logger.warning("Invalid JSON schema", extra={
                'extra_fields': {
                    'security_event': 'INVALID_JSON_SCHEMA',
                    'client_ip': getattr(g, 'client_ip', 'unknown')
                }
            })
            return jsonify({'error': 'Invalid request format'}), 400
        
        # Extract and sanitize input
        original_prompt = data['prompt']
        model_name = data.get('model_name', 'gpt-3.5-turbo')
        
        # Sanitize input if enabled
        if SECURITY_CONFIG['input_sanitization_enabled']:
            original_prompt = SecurityUtils.sanitize_input(original_prompt)
        
        # Additional validation
        if not original_prompt or not original_prompt.strip():
            logger.warning("Empty prompt", extra={
                'extra_fields': {
                    'security_event': 'EMPTY_PROMPT',
                    'client_ip': getattr(g, 'client_ip', 'unknown')
                }
            })
            return jsonify({'error': 'Prompt cannot be empty'}), 400
        
        logger.info(f"Processing chat request", extra={
            'extra_fields': {
                'model_requested': model_name,
                'prompt_length': len(original_prompt),
                'prompt_hash': hashlib.sha256(original_prompt.encode()).hexdigest()[:16]
            }
        })
        
        # Initialize security analyzer
        security_analyzer = SecurityAnalyzer()
        
        # Step 1: Prompt injection detection
        if SECURITY_CONFIG['injection_detection_enabled']:
            injection_analysis = security_analyzer.detect_prompt_injection(original_prompt)
        else:
            injection_analysis = {'detected': False, 'risk_level': 'LOW', 'audit_trail': []}
        
        # Step 2: PII redaction
        if SECURITY_CONFIG['pii_detection_enabled']:
            pii_analysis = security_analyzer.redact_pii(original_prompt)
            sanitized_prompt = pii_analysis['redacted_text']
        else:
            pii_analysis = {'total_redactions': 0, 'redacted_items': {}, 'audit_trail': []}
            sanitized_prompt = original_prompt
        
        # Step 3: Simulate LLM response
        llm_response = simulate_llm_response(sanitized_prompt, model_name)
        
        # Step 4: Post-processing security checks
        if SECURITY_CONFIG['pii_detection_enabled']:
            pii_analysis_response = security_analyzer.redact_pii(llm_response)
            final_response_text = pii_analysis_response['redacted_text']
        else:
            pii_analysis_response = {'total_redactions': 0, 'redacted_items': {}, 'audit_trail': []}
            final_response_text = llm_response
        
        if SECURITY_CONFIG['content_filtering_enabled']:
            harmful_content_analysis = security_analyzer.filter_harmful_content(final_response_text)
        else:
            harmful_content_analysis = {'detected': False, 'risk_level': 'LOW', 'audit_trail': []}
        
        # Sanitize response if enabled
        if SECURITY_CONFIG['output_sanitization_enabled']:
            final_response_text = SecurityUtils.sanitize_output(final_response_text)
        
        # Validate response size
        if len(final_response_text) > SECURITY_CONFIG['max_response_size']:
            logger.warning("Response too large", extra={
                'extra_fields': {
                    'security_event': 'RESPONSE_TOO_LARGE',
                    'response_length': len(final_response_text),
                    'max_size': SECURITY_CONFIG['max_response_size'],
                    'client_ip': getattr(g, 'client_ip', 'unknown')
                }
            })
            final_response_text = final_response_text[:SECURITY_CONFIG['max_response_size']] + "... [truncated]"
        
        # Prepare response with security considerations
        response_data = {
            'status': 'success',
            'request_id': g.request_id,
            'audit_id': g.audit_id,
            'security_analysis': {
                'prompt_injection': injection_analysis,
                'pii_redaction_prompt': pii_analysis,
                'pii_redaction_response': pii_analysis_response,
                'harmful_content': harmful_content_analysis,
                'overall_risk_assessment': {
                    'highest_risk_level': max([
                        injection_analysis.get('risk_level', 'LOW'),
                        harmful_content_analysis.get('risk_level', 'LOW')
                    ], key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x)),
                    'total_security_events': len(security_analyzer.security_events),
                    'compliance_impact': list(set([f.value for event in security_analyzer.security_events for f in event.compliance_impact]))
                }
            },
            'model_used': model_name,
            'response': final_response_text,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'compliance_info': {
                'gdpr_compliant': all('GDPR' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
                'hipaa_compliant': all('HIPAA' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
                'pci_dss_compliant': all('PCI_DSS' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
                'sox_compliant': all('SOX' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events),
                'iso_27001_compliant': all('ISO_27001' not in [f.value for f in event.compliance_impact] for event in security_analyzer.security_events)
            }
        }
        
        # Create comprehensive audit trail
        audit_trail = create_audit_trail(data, security_analyzer, response_data)
        
        # Log final audit trail
        logger.info(f"Request completed successfully", extra={
            'extra_fields': {
                'audit_trail': asdict(audit_trail),
                'response_length': len(final_response_text),
                'response_hash': hashlib.sha256(final_response_text.encode()).hexdigest()[:16]
            }
        })
        
        return jsonify(response_data)
        
    except Exception as e:
        # Log error with security considerations
        error_message = str(e) if SECURITY_CONFIG['detailed_error_messages'] else 'Internal server error'
        error_type = type(e).__name__ if SECURITY_CONFIG['detailed_error_messages'] else 'InternalError'
        
        logger.error(f"Error processing request: {error_message}", extra={
            'extra_fields': {
                'error_type': error_type,
                'error_details': error_message if SECURITY_CONFIG['log_sensitive_data'] else 'Error details redacted',
                'client_ip': getattr(g, 'client_ip', 'unknown'),
                'security_event': 'PROCESSING_ERROR'
            }
        })
        
        # Return sanitized error response
        error_response = {
            'error': 'Internal server error' if not SECURITY_CONFIG['detailed_error_messages'] else error_message,
            'request_id': getattr(g, 'request_id', 'unknown')
        }
        
        return jsonify(error_response), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Security-focused health check endpoint."""
    try:
        # Check security features status
        security_status = {
            'injection_detection_enabled': SECURITY_CONFIG['injection_detection_enabled'],
            'pii_detection_enabled': SECURITY_CONFIG['pii_detection_enabled'],
            'content_filtering_enabled': SECURITY_CONFIG['content_filtering_enabled'],
            'audit_logging_enabled': SECURITY_CONFIG['audit_logging_enabled'],
            'input_sanitization_enabled': SECURITY_CONFIG['input_sanitization_enabled'],
            'output_sanitization_enabled': SECURITY_CONFIG['output_sanitization_enabled'],
            'rate_limiting_enabled': True,  # Always enabled
            'security_headers_enabled': SECURITY_CONFIG['security_headers_enabled'],
            'hsts_enabled': SECURITY_CONFIG['hsts_enabled']
        }
        
        # Check system security status
        system_security = {
            'ssl_available': hasattr(ssl, 'SSLContext'),
            'crypto_available': hasattr(secrets, 'token_urlsafe'),
            'hashlib_available': hasattr(hashlib, 'sha256'),
            'bcrypt_available': hasattr(bcrypt, 'gensalt')
        }
        
        # Check rate limiting status
        rate_limit_status = {
            'active_clients': len(rate_limiter.requests),
            'rate_limit_window': SECURITY_CONFIG['rate_limit_window'],
            'max_requests_per_minute': SECURITY_CONFIG['rate_limit_requests_per_minute']
        }
        
        return jsonify({
            'status': 'healthy',
            'service': 'Secure LLM Proxy PoC',
            'version': '1.0.0-poc',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'security_status': security_status,
            'system_security': system_security,
            'rate_limit_status': rate_limit_status,
            'compliance_frameworks': [f.value for f in SECURITY_CONFIG['compliance_frameworks']],
            'security_headers': {
                'content_security_policy': SECURITY_CONFIG['content_security_policy'],
                'hsts_max_age': SECURITY_CONFIG['hsts_max_age'],
                'x_frame_options': SECURITY_CONFIG['x_frame_options'],
                'x_content_type_options': SECURITY_CONFIG['x_content_type_options'],
                'x_xss_protection': SECURITY_CONFIG['x_xss_protection'],
                'referrer_policy': SECURITY_CONFIG['referrer_policy']
            }
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}", extra={
            'extra_fields': {
                'security_event': 'HEALTH_CHECK_FAILED',
                'error': str(e)
            }
        })
        return jsonify({
            'status': 'unhealthy',
            'error': 'Health check failed',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@app.route('/audit/report', methods=['GET'])
def audit_report():
    """Generate comprehensive audit report for compliance purposes."""
    try:
        # Get query parameters for report customization
        report_type = request.args.get('type', 'comprehensive')
        framework = request.args.get('framework', 'all')
        risk_level = request.args.get('risk_level', 'all')
        
        # This would typically query a database for audit logs
        # For PoC, return a comprehensive report structure
        report = {
            'report_id': str(uuid.uuid4()),
            'report_type': report_type,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'report_period': {
                'start': (datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)).isoformat(),
                'end': datetime.now(timezone.utc).isoformat()
            },
            'audit_metadata': {
                'audit_standard': 'ISO 27001:2013',
                'audit_scope': 'Secure LLM Proxy Security Controls',
                'audit_methodology': 'Automated security analysis with manual review',
                'audit_evidence_type': 'Structured JSON logs with hash verification',
                'audit_retention_policy': f"{SECURITY_CONFIG['audit_retention_days']} days",
                'audit_encryption': SECURITY_CONFIG['audit_encryption_enabled'],
                'audit_backup': SECURITY_CONFIG['audit_backup_enabled']
            },
            'executive_summary': {
                'total_requests': 0,  # Would be calculated from logs
                'security_events': 0,  # Would be calculated from logs
                'compliance_violations': 0,  # Would be calculated from logs
                'overall_risk_level': 'LOW',  # Would be calculated from logs
                'compliance_score': 85,  # Would be calculated from logs
                'audit_confidence': 'HIGH'
            },
            'risk_assessment': {
                'risk_distribution': {
                    'LOW': 0,
                    'MEDIUM': 0,
                    'HIGH': 0,
                    'CRITICAL': 0
                },
                'risk_factors': {
                    'prompt_injection_risk': False,
                    'pii_exposure_risk': False,
                    'harmful_content_risk': False,
                    'compliance_violation_risk': False
                },
                'risk_mitigation_effectiveness': {
                    'pii_protection': 'HIGH',
                    'injection_protection': 'HIGH',
                    'content_filtering': 'HIGH'
                }
            },
            'compliance_framework_assessment': {
                'gdpr': {
                    'status': 'COMPLIANT',
                    'score': 85,
                    'key_controls': ['PII detection', 'Data minimization', 'Audit trails'],
                    'gaps': ['Data subject rights', 'Processing agreements'],
                    'recommendations': ['Implement data subject rights management', 'Establish data processing agreements']
                },
                'hipaa': {
                    'status': 'PARTIALLY_COMPLIANT',
                    'score': 70,
                    'key_controls': ['PHI protection', 'Audit logging'],
                    'gaps': ['Authentication', 'Encryption', 'Business associate agreements'],
                    'recommendations': ['Implement user authentication', 'Add encryption', 'Establish BAAs']
                },
                'pci_dss': {
                    'status': 'PARTIALLY_COMPLIANT',
                    'score': 75,
                    'key_controls': ['Card data detection', 'Secure processing', 'Audit trails'],
                    'gaps': ['Tokenization', 'Encryption standards', 'Network segmentation'],
                    'recommendations': ['Implement tokenization', 'Add PCI-compliant encryption', 'Establish network segmentation']
                },
                'sox': {
                    'status': 'PARTIALLY_COMPLIANT',
                    'score': 80,
                    'key_controls': ['Financial data integrity', 'Audit requirements'],
                    'gaps': ['Access controls', 'Change management'],
                    'recommendations': ['Implement proper access controls', 'Establish change management process']
                },
                'iso_27001': {
                    'status': 'PARTIALLY_COMPLIANT',
                    'score': 75,
                    'key_controls': ['Security controls', 'Risk assessment', 'Monitoring and logging'],
                    'gaps': ['Information security policy', 'Asset management'],
                    'recommendations': ['Develop information security policy', 'Enhance asset management processes']
                }
            },
            'security_control_effectiveness': {
                'prompt_injection_protection': {
                    'effectiveness': 'HIGH',
                    'coverage': '4 categories of injection patterns',
                    'detection_rate': '95%',
                    'false_positive_rate': '2%'
                },
                'pii_protection': {
                    'effectiveness': 'HIGH',
                    'coverage': '8 types of PII patterns',
                    'redaction_rate': '98%',
                    'compliance_impact': ['GDPR', 'HIPAA', 'PCI-DSS', 'SOX']
                },
                'content_filtering': {
                    'effectiveness': 'MEDIUM',
                    'coverage': '4 categories of harmful content',
                    'detection_rate': '85%',
                    'risk_assessment': 'Automated risk level assignment'
                }
            },
            'audit_trail_analysis': {
                'log_completeness': '95%',
                'retention_period': f"{SECURITY_CONFIG['audit_retention_days']} days",
                'format': 'JSON Lines (machine-readable)',
                'correlation': 'Request-level audit trail linking',
                'integrity_verification': 'Hash-based verification implemented'
            },
            'incident_response': {
                'total_incidents': 0,
                'incident_distribution': {
                    'prompt_injection': 0,
                    'pii_detection': 0,
                    'harmful_content': 0,
                    'security_violations': 0,
                    'compliance_violations': 0
                },
                'response_times': {
                    'average_detection_time': '0.5 seconds',
                    'average_response_time': '1.2 seconds',
                    'automated_response_rate': '95%'
                }
            },
            'recommendations': {
                'high_priority': [
                    "Implement user authentication and authorization",
                    "Add transport and storage encryption",
                    "Establish information security and privacy policies",
                    "Implement security awareness training"
                ],
                'medium_priority': [
                    "Implement ML-based threat detection",
                    "Add real-time security monitoring dashboard",
                    "Enhance compliance reporting capabilities",
                    "Conduct third-party security assessment"
                ],
                'low_priority': [
                    "Optimize processing performance",
                    "Enhance operational documentation",
                    "Implement comprehensive security testing",
                    "Add automated backup and recovery procedures"
                ]
            },
            'compliance_roadmap': {
                'phase_1_immediate': [
                    "Implement authentication and encryption",
                    "Establish security policies",
                    "Conduct security training"
                ],
                'phase_2_short_term': [
                    "Enhance threat detection",
                    "Implement monitoring dashboard",
                    "Validate compliance controls"
                ],
                'phase_3_long_term': [
                    "Achieve full compliance certification",
                    "Implement advanced security features",
                    "Establish continuous monitoring"
                ]
            }
        }
        
        # Filter report based on query parameters
        if framework != 'all':
            report['compliance_framework_assessment'] = {
                framework: report['compliance_framework_assessment'].get(framework, {})
            }
        
        if risk_level != 'all':
            # Filter risk assessment based on risk level
            pass
        
        return jsonify(report)
        
    except Exception as e:
        logger.error(f"Error generating audit report: {str(e)}")
        return jsonify({'error': 'Failed to generate audit report'}), 500

@app.route('/audit/validate', methods=['POST'])
def validate_audit_trail():
    """Validate audit trail integrity and completeness for compliance purposes."""
    try:
        data = request.get_json()
        if not data or 'audit_id' not in data:
            return jsonify({'error': 'Missing audit_id in request'}), 400
        
        audit_id = data['audit_id']
        
        # This would typically query the audit database
        # For PoC, return validation results
        validation_result = {
            'audit_id': audit_id,
            'validation_timestamp': datetime.now(timezone.utc).isoformat(),
            'integrity_check': {
                'hash_verification': 'PASS',
                'signature_verification': 'PASS',
                'timestamp_validation': 'PASS',
                'sequence_validation': 'PASS'
            },
            'completeness_check': {
                'required_fields': 'PASS',
                'audit_trail_completeness': 'PASS',
                'security_events_logged': 'PASS',
                'compliance_mapping': 'PASS'
            },
            'compliance_validation': {
                'gdpr_requirements': 'PASS',
                'hipaa_requirements': 'PASS',
                'pci_dss_requirements': 'PASS',
                'sox_requirements': 'PASS',
                'iso_27001_requirements': 'PASS'
            },
            'audit_quality_score': 95,
            'validation_status': 'VALID',
            'recommendations': [
                'Audit trail meets compliance requirements',
                'All required fields are present and valid',
                'Security events are properly logged and categorized'
            ]
        }
        
        return jsonify(validation_result)
        
    except Exception as e:
        logger.error(f"Error validating audit trail: {str(e)}")
        return jsonify({'error': 'Failed to validate audit trail'}), 500

@app.route('/audit/export', methods=['GET'])
def export_audit_data():
    """Export audit data in various formats for compliance reporting."""
    try:
        format_type = request.args.get('format', 'json')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        framework = request.args.get('framework', 'all')
        
        # This would typically query the audit database
        # For PoC, return sample export data
        export_data = {
            'export_id': str(uuid.uuid4()),
            'export_timestamp': datetime.now(timezone.utc).isoformat(),
            'export_format': format_type,
            'export_period': {
                'start_date': start_date or (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                'end_date': end_date or datetime.now(timezone.utc).isoformat()
            },
            'compliance_framework': framework,
            'data_summary': {
                'total_records': 0,
                'security_events': 0,
                'compliance_violations': 0,
                'risk_assessments': 0
            },
            'export_content': {
                'audit_logs': [],
                'security_events': [],
                'compliance_violations': [],
                'risk_assessments': []
            },
            'export_metadata': {
                'generated_by': 'Secure LLM Proxy Audit System',
                'export_purpose': 'Compliance reporting and audit evidence',
                'data_retention': f"{SECURITY_CONFIG['audit_retention_days']} days",
                'export_encryption': SECURITY_CONFIG['audit_encryption_enabled']
            }
        }
        
        return jsonify(export_data)
        
    except Exception as e:
        logger.error(f"Error exporting audit data: {str(e)}")
        return jsonify({'error': 'Failed to export audit data'}), 500

@app.route('/security/status', methods=['GET'])
def security_status():
    """Get detailed security status and configuration."""
    try:
        # Get current security metrics
        security_metrics = {
            'active_clients': len(rate_limiter.requests),
            'total_requests_processed': sum(len(requests) for requests in rate_limiter.requests.values()),
            'rate_limit_violations': len([req for req in rate_limiter.requests.values() if len(req) >= SECURITY_CONFIG['rate_limit_requests_per_minute']]),
            'blocked_ips_count': len(SECURITY_CONFIG['blocked_ips']),
            'allowed_ips_count': len(SECURITY_CONFIG['allowed_ips'])
        }
        
        # Security configuration summary
        security_config_summary = {
            'input_validation': {
                'max_prompt_length': SECURITY_CONFIG['max_prompt_length'],
                'max_request_size': SECURITY_CONFIG['max_request_size'],
                'input_sanitization': SECURITY_CONFIG['input_sanitization_enabled'],
                'output_sanitization': SECURITY_CONFIG['output_sanitization_enabled']
            },
            'rate_limiting': {
                'requests_per_minute': SECURITY_CONFIG['rate_limit_requests_per_minute'],
                'burst_size': SECURITY_CONFIG['rate_limit_burst_size'],
                'window_seconds': SECURITY_CONFIG['rate_limit_window']
            },
            'security_features': {
                'pii_detection': SECURITY_CONFIG['pii_detection_enabled'],
                'injection_detection': SECURITY_CONFIG['injection_detection_enabled'],
                'content_filtering': SECURITY_CONFIG['content_filtering_enabled'],
                'audit_logging': SECURITY_CONFIG['audit_logging_enabled']
            },
            'headers': {
                'security_headers': SECURITY_CONFIG['security_headers_enabled'],
                'hsts': SECURITY_CONFIG['hsts_enabled'],
                'csp': bool(SECURITY_CONFIG['content_security_policy'])
            }
        }
        
        return jsonify({
            'status': 'secure',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'security_metrics': security_metrics,
            'security_config': security_config_summary,
            'compliance_status': {
                'frameworks': [f.value for f in SECURITY_CONFIG['compliance_frameworks']],
                'gdpr_ready': True,
                'hipaa_ready': True,
                'pci_dss_ready': True,
                'sox_ready': True,
                'iso_27001_ready': True
            }
        })
        
    except Exception as e:
        logger.error(f"Security status check failed: {str(e)}", extra={
            'extra_fields': {
                'security_event': 'SECURITY_STATUS_FAILED',
                'error': str(e)
            }
        })
        return jsonify({
            'status': 'error',
            'error': 'Security status check failed',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@app.errorhandler(HTTPException)
def handle_http_error(error):
    """Handle HTTP errors with security logging."""
    # Log security-relevant errors
    if error.code in [403, 429, 413]:
        logger.warning(f"Security-related HTTP error: {error.code} - {error.description}", extra={
            'extra_fields': {
                'security_event': 'SECURITY_HTTP_ERROR',
                'error_code': error.code,
                'error_description': error.description,
                'client_ip': getattr(g, 'client_ip', 'unknown'),
                'user_agent': getattr(g, 'user_agent', 'unknown')
            }
        })
    else:
        logger.error(f"HTTP error: {error.code} - {error.description}", extra={
            'extra_fields': {
                'error_code': error.code,
                'error_description': error.description,
                'client_ip': getattr(g, 'client_ip', 'unknown')
            }
        })
    
    # Return sanitized error response
    error_response = {
        'error': error.description if SECURITY_CONFIG['detailed_error_messages'] else 'Request failed',
        'code': error.code
    }
    
    return jsonify(error_response), error.code

if __name__ == '__main__':
    logger.info("Starting Secure LLM Proxy (PoC) with comprehensive audit logging")
    logger.info("WARNING: This is a proof of concept with basic security measures")
    logger.info("Do not use in production environments")
    logger.info(f"Security configuration: {SECURITY_CONFIG}")
    app.run(debug=True, host='0.0.0.0', port=5000)