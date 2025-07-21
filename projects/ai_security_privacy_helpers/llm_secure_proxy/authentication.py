"""
Enterprise Authentication System
Secure LLM Interaction Proxy

This module provides comprehensive authentication and authorization features
for enterprise deployment with user management, API keys, MFA, and session security.
"""

import os
import json
import uuid
import secrets
import hashlib
import hmac
import time
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import threading
from contextlib import contextmanager

import bcrypt
import pyotp
from flask import request, session, g, current_app
from werkzeug.security import safe_str_cmp

# Authentication configuration
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
    'mfa_method': 'totp',  # 'totp', 'sms', 'email'
    'api_key_expiry_days': 365,
    'max_api_keys_per_user': 5,
    'session_cleanup_interval_minutes': 60,
    'database_path': 'auth.db',
    'backup_enabled': True,
    'audit_logging': True
}

# User roles and permissions
class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"
    AUDITOR = "auditor"

class Permission(Enum):
    CHAT_ACCESS = "chat_access"
    AUDIT_ACCESS = "audit_access"
    USER_MANAGEMENT = "user_management"
    API_KEY_MANAGEMENT = "api_key_management"
    SECURITY_CONFIG = "security_config"
    SYSTEM_ADMIN = "system_admin"

# Role permissions mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        Permission.CHAT_ACCESS,
        Permission.AUDIT_ACCESS,
        Permission.USER_MANAGEMENT,
        Permission.API_KEY_MANAGEMENT,
        Permission.SECURITY_CONFIG,
        Permission.SYSTEM_ADMIN
    ],
    UserRole.USER: [
        Permission.CHAT_ACCESS,
        Permission.API_KEY_MANAGEMENT
    ],
    UserRole.READONLY: [
        Permission.CHAT_ACCESS
    ],
    UserRole.AUDITOR: [
        Permission.AUDIT_ACCESS
    ]
}

# Data classes for structured data
@dataclass
class User:
    """User account information."""
    id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    is_locked: bool
    failed_attempts: int
    last_login: Optional[str]
    created_at: str
    updated_at: str
    mfa_enabled: bool
    mfa_secret: Optional[str]
    password_hash: str

@dataclass
class ApiKey:
    """API key information."""
    id: str
    user_id: str
    name: str
    key_hash: str
    permissions: List[Permission]
    is_active: bool
    created_at: str
    expires_at: Optional[str]
    last_used: Optional[str]
    usage_count: int

@dataclass
class Session:
    """User session information."""
    id: str
    user_id: str
    session_token: str
    ip_address: str
    user_agent: str
    created_at: str
    expires_at: str
    is_active: bool
    last_activity: str

@dataclass
class AuthEvent:
    """Authentication event for audit logging."""
    id: str
    timestamp: str
    event_type: str
    user_id: Optional[str]
    ip_address: str
    user_agent: str
    success: bool
    details: Dict[str, Any]
    session_id: Optional[str]

class AuthenticationError(Exception):
    """Custom exception for authentication errors."""
    pass

class AuthorizationError(Exception):
    """Custom exception for authorization errors."""
    pass

class DatabaseManager:
    """Database manager for authentication data."""
    
    def __init__(self, db_path: str = AUTH_CONFIG['database_path']):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize database with required tables."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    is_locked BOOLEAN DEFAULT FALSE,
                    failed_attempts INTEGER DEFAULT 0,
                    last_login TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    mfa_secret TEXT,
                    password_hash TEXT NOT NULL
                )
            ''')
            
            # API keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    usage_count INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    last_activity TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Auth events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    details TEXT NOT NULL,
                    session_id TEXT
                )
            ''')
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with proper error handling."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    def execute_query(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Execute a query and return results."""
        with self.lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return cursor.fetchall()
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute an update query and return affected rows."""
        with self.lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount

class UserManager:
    """User management functionality."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def create_user(self, username: str, email: str, password: str, 
                   role: UserRole = UserRole.USER, mfa_enabled: bool = False) -> User:
        """Create a new user account."""
        # Validate input
        self._validate_username(username)
        self._validate_email(email)
        self._validate_password(password)
        
        # Check if user already exists
        if self.get_user_by_username(username):
            raise AuthenticationError("Username already exists")
        
        if self.get_user_by_email(email):
            raise AuthenticationError("Email already exists")
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Generate MFA secret if enabled
        mfa_secret = None
        if mfa_enabled:
            mfa_secret = pyotp.random_base32()
        
        # Create user
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        user = User(
            id=user_id,
            username=username,
            email=email,
            role=role,
            is_active=True,
            is_locked=False,
            failed_attempts=0,
            last_login=None,
            created_at=now,
            updated_at=now,
            mfa_enabled=mfa_enabled,
            mfa_secret=mfa_secret,
            password_hash=password_hash
        )
        
        # Save to database
        self.db.execute_update('''
            INSERT INTO users (id, username, email, role, is_active, is_locked, 
                             failed_attempts, last_login, created_at, updated_at, 
                             mfa_enabled, mfa_secret, password_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user.id, user.username, user.email, user.role.value, user.is_active,
              user.is_locked, user.failed_attempts, user.last_login, user.created_at,
              user.updated_at, user.mfa_enabled, user.mfa_secret, user.password_hash))
        
        # Log event
        self._log_auth_event("USER_CREATED", user.id, True, {"username": username, "role": role.value})
        
        return user
    
    def authenticate_user(self, username: str, password: str, 
                         mfa_code: Optional[str] = None) -> Tuple[User, str]:
        """Authenticate a user and return user object and session token."""
        user = self.get_user_by_username(username)
        if not user:
            self._log_auth_event("LOGIN_FAILED", None, False, {"username": username, "reason": "user_not_found"})
            raise AuthenticationError("Invalid credentials")
        
        # Check if user is locked
        if user.is_locked:
            self._log_auth_event("LOGIN_FAILED", user.id, False, {"username": username, "reason": "account_locked"})
            raise AuthenticationError("Account is locked")
        
        # Check if user is active
        if not user.is_active:
            self._log_auth_event("LOGIN_FAILED", user.id, False, {"username": username, "reason": "account_inactive"})
            raise AuthenticationError("Account is inactive")
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            self._increment_failed_attempts(user)
            self._log_auth_event("LOGIN_FAILED", user.id, False, {"username": username, "reason": "invalid_password"})
            raise AuthenticationError("Invalid credentials")
        
        # Verify MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                self._log_auth_event("LOGIN_FAILED", user.id, False, {"username": username, "reason": "mfa_required"})
                raise AuthenticationError("MFA code required")
            
            if not self._verify_mfa_code(user.mfa_secret, mfa_code):
                self._log_auth_event("LOGIN_FAILED", user.id, False, {"username": username, "reason": "invalid_mfa"})
                raise AuthenticationError("Invalid MFA code")
        
        # Reset failed attempts
        self._reset_failed_attempts(user)
        
        # Update last login
        self._update_last_login(user)
        
        # Create session
        session_token = self._create_session(user)
        
        # Log successful login
        self._log_auth_event("LOGIN_SUCCESS", user.id, True, {"username": username})
        
        return user, session_token
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        rows = self.db.execute_query("SELECT * FROM users WHERE username = ?", (username,))
        if not rows:
            return None
        return self._row_to_user(rows[0])
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        rows = self.db.execute_query("SELECT * FROM users WHERE email = ?", (email,))
        if not rows:
            return None
        return self._row_to_user(rows[0])
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        rows = self.db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
        if not rows:
            return None
        return self._row_to_user(rows[0])
    
    def update_user(self, user_id: str, **kwargs) -> User:
        """Update user information."""
        user = self.get_user_by_id(user_id)
        if not user:
            raise AuthenticationError("User not found")
        
        # Update allowed fields
        allowed_fields = ['email', 'role', 'is_active', 'mfa_enabled']
        update_fields = []
        update_values = []
        
        for field, value in kwargs.items():
            if field in allowed_fields:
                update_fields.append(f"{field} = ?")
                update_values.append(value)
        
        if not update_fields:
            return user
        
        update_values.append(datetime.now(timezone.utc).isoformat())
        update_values.append(user_id)
        
        query = f"UPDATE users SET {', '.join(update_fields)}, updated_at = ? WHERE id = ?"
        self.db.execute_update(query, tuple(update_values))
        
        # Log event
        self._log_auth_event("USER_UPDATED", user_id, True, {"updated_fields": list(kwargs.keys())})
        
        return self.get_user_by_id(user_id)
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Change user password."""
        user = self.get_user_by_id(user_id)
        if not user:
            raise AuthenticationError("User not found")
        
        # Verify old password
        if not bcrypt.checkpw(old_password.encode('utf-8'), user.password_hash.encode('utf-8')):
            self._log_auth_event("PASSWORD_CHANGE_FAILED", user_id, False, {"reason": "invalid_old_password"})
            raise AuthenticationError("Invalid old password")
        
        # Validate new password
        self._validate_password(new_password)
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        self.db.execute_update(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (new_password_hash, datetime.now(timezone.utc).isoformat(), user_id)
        )
        
        # Log event
        self._log_auth_event("PASSWORD_CHANGED", user_id, True, {})
        
        return True
    
    def _validate_username(self, username: str):
        """Validate username format."""
        if not username or len(username) < 3 or len(username) > 50:
            raise AuthenticationError("Username must be 3-50 characters long")
        
        if not username.replace('_', '').replace('-', '').isalnum():
            raise AuthenticationError("Username can only contain letters, numbers, underscores, and hyphens")
    
    def _validate_email(self, email: str):
        """Validate email format."""
        if not email or '@' not in email or '.' not in email:
            raise AuthenticationError("Invalid email format")
    
    def _validate_password(self, password: str):
        """Validate password strength."""
        if len(password) < AUTH_CONFIG['password_min_length']:
            raise AuthenticationError(f"Password must be at least {AUTH_CONFIG['password_min_length']} characters long")
        
        if AUTH_CONFIG['password_require_uppercase'] and not any(c.isupper() for c in password):
            raise AuthenticationError("Password must contain at least one uppercase letter")
        
        if AUTH_CONFIG['password_require_lowercase'] and not any(c.islower() for c in password):
            raise AuthenticationError("Password must contain at least one lowercase letter")
        
        if AUTH_CONFIG['password_require_numbers'] and not any(c.isdigit() for c in password):
            raise AuthenticationError("Password must contain at least one number")
        
        if AUTH_CONFIG['password_require_special'] and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            raise AuthenticationError("Password must contain at least one special character")
    
    def _increment_failed_attempts(self, user: User):
        """Increment failed login attempts."""
        new_attempts = user.failed_attempts + 1
        is_locked = new_attempts >= AUTH_CONFIG['max_failed_attempts']
        
        self.db.execute_update(
            "UPDATE users SET failed_attempts = ?, is_locked = ?, updated_at = ? WHERE id = ?",
            (new_attempts, is_locked, datetime.now(timezone.utc).isoformat(), user.id)
        )
    
    def _reset_failed_attempts(self, user: User):
        """Reset failed login attempts."""
        self.db.execute_update(
            "UPDATE users SET failed_attempts = 0, is_locked = FALSE, updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), user.id)
        )
    
    def _update_last_login(self, user: User):
        """Update user's last login time."""
        self.db.execute_update(
            "UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(), user.id)
        )
    
    def _verify_mfa_code(self, secret: str, code: str) -> bool:
        """Verify MFA TOTP code."""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code)
        except Exception:
            return False
    
    def _create_session(self, user: User) -> str:
        """Create a new session for the user."""
        session_manager = SessionManager(self.db)
        return session_manager.create_session(user.id)
    
    def _log_auth_event(self, event_type: str, user_id: Optional[str], 
                       success: bool, details: Dict[str, Any]):
        """Log authentication event."""
        if not AUTH_CONFIG['audit_logging']:
            return
        
        event_manager = AuthEventManager(self.db)
        event_manager.log_event(event_type, user_id, success, details)
    
    def _row_to_user(self, row) -> User:
        """Convert database row to User object."""
        return User(
            id=row['id'],
            username=row['username'],
            email=row['email'],
            role=UserRole(row['role']),
            is_active=bool(row['is_active']),
            is_locked=bool(row['is_locked']),
            failed_attempts=row['failed_attempts'],
            last_login=row['last_login'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            mfa_enabled=bool(row['mfa_enabled']),
            mfa_secret=row['mfa_secret'],
            password_hash=row['password_hash']
        )

class ApiKeyManager:
    """API key management functionality."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def create_api_key(self, user_id: str, name: str, 
                      permissions: List[Permission] = None) -> Tuple[str, ApiKey]:
        """Create a new API key for a user."""
        # Check if user exists
        user_manager = UserManager(self.db)
        user = user_manager.get_user_by_id(user_id)
        if not user:
            raise AuthenticationError("User not found")
        
        # Check API key limit
        existing_keys = self.get_user_api_keys(user_id)
        if len(existing_keys) >= AUTH_CONFIG['max_api_keys_per_user']:
            raise AuthenticationError("Maximum number of API keys reached")
        
        # Generate API key
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Set default permissions if not specified
        if not permissions:
            permissions = ROLE_PERMISSIONS.get(user.role, [])
        
        # Create API key record
        key_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        expires_at = (datetime.now(timezone.utc) + timedelta(days=AUTH_CONFIG['api_key_expiry_days'])).isoformat()
        
        api_key_obj = ApiKey(
            id=key_id,
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            permissions=permissions,
            is_active=True,
            created_at=now,
            expires_at=expires_at,
            last_used=None,
            usage_count=0
        )
        
        # Save to database
        self.db.execute_update('''
            INSERT INTO api_keys (id, user_id, name, key_hash, permissions, is_active, 
                                created_at, expires_at, last_used, usage_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (api_key_obj.id, api_key_obj.user_id, api_key_obj.name, api_key_obj.key_hash,
              json.dumps([p.value for p in api_key_obj.permissions]), api_key_obj.is_active,
              api_key_obj.created_at, api_key_obj.expires_at, api_key_obj.last_used,
              api_key_obj.usage_count))
        
        # Log event
        self._log_auth_event("API_KEY_CREATED", user_id, True, {"key_name": name})
        
        return api_key, api_key_obj
    
    def validate_api_key(self, api_key: str) -> Optional[Tuple[User, List[Permission]]]:
        """Validate API key and return user and permissions."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        rows = self.db.execute_query(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = TRUE", (key_hash,)
        )
        
        if not rows:
            return None
        
        key_data = rows[0]
        
        # Check expiration
        if key_data['expires_at']:
            expires_at = datetime.fromisoformat(key_data['expires_at'])
            if datetime.now(timezone.utc) > expires_at:
                return None
        
        # Get user
        user_manager = UserManager(self.db)
        user = user_manager.get_user_by_id(key_data['user_id'])
        if not user or not user.is_active:
            return None
        
        # Parse permissions
        permissions = [Permission(p) for p in json.loads(key_data['permissions'])]
        
        # Update usage statistics
        self._update_api_key_usage(key_data['id'])
        
        return user, permissions
    
    def get_user_api_keys(self, user_id: str) -> List[ApiKey]:
        """Get all API keys for a user."""
        rows = self.db.execute_query(
            "SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
        )
        
        return [self._row_to_api_key(row) for row in rows]
    
    def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        """Revoke an API key."""
        # Verify ownership
        rows = self.db.execute_query(
            "SELECT * FROM api_keys WHERE id = ? AND user_id = ?", (key_id, user_id)
        )
        
        if not rows:
            raise AuthenticationError("API key not found")
        
        # Revoke key
        self.db.execute_update(
            "UPDATE api_keys SET is_active = FALSE WHERE id = ?", (key_id,)
        )
        
        # Log event
        self._log_auth_event("API_KEY_REVOKED", user_id, True, {"key_id": key_id})
        
        return True
    
    def _update_api_key_usage(self, key_id: str):
        """Update API key usage statistics."""
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute_update(
            "UPDATE api_keys SET last_used = ?, usage_count = usage_count + 1 WHERE id = ?",
            (now, key_id)
        )
    
    def _log_auth_event(self, event_type: str, user_id: str, success: bool, details: Dict[str, Any]):
        """Log authentication event."""
        if not AUTH_CONFIG['audit_logging']:
            return
        
        event_manager = AuthEventManager(self.db)
        event_manager.log_event(event_type, user_id, success, details)
    
    def _row_to_api_key(self, row) -> ApiKey:
        """Convert database row to ApiKey object."""
        return ApiKey(
            id=row['id'],
            user_id=row['user_id'],
            name=row['name'],
            key_hash=row['key_hash'],
            permissions=[Permission(p) for p in json.loads(row['permissions'])],
            is_active=bool(row['is_active']),
            created_at=row['created_at'],
            expires_at=row['expires_at'],
            last_used=row['last_used'],
            usage_count=row['usage_count']
        )

class SessionManager:
    """Session management functionality."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def create_session(self, user_id: str) -> str:
        """Create a new session for a user."""
        session_token = secrets.token_urlsafe(32)
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=AUTH_CONFIG['session_timeout_minutes'])).isoformat()
        
        session_obj = Session(
            id=session_id,
            user_id=user_id,
            session_token=session_token,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            created_at=now,
            expires_at=expires_at,
            is_active=True,
            last_activity=now
        )
        
        # Save to database
        self.db.execute_update('''
            INSERT INTO sessions (id, user_id, session_token, ip_address, user_agent, 
                                created_at, expires_at, is_active, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session_obj.id, session_obj.user_id, session_obj.session_token,
              session_obj.ip_address, session_obj.user_agent, session_obj.created_at,
              session_obj.expires_at, session_obj.is_active, session_obj.last_activity))
        
        return session_token
    
    def validate_session(self, session_token: str) -> Optional[Tuple[User, Session]]:
        """Validate session token and return user and session."""
        rows = self.db.execute_query(
            "SELECT * FROM sessions WHERE session_token = ? AND is_active = TRUE", (session_token,)
        )
        
        if not rows:
            return None
        
        session_data = rows[0]
        
        # Check expiration
        expires_at = datetime.fromisoformat(session_data['expires_at'])
        if datetime.now(timezone.utc) > expires_at:
            self._invalidate_session(session_data['id'])
            return None
        
        # Get user
        user_manager = UserManager(self.db)
        user = user_manager.get_user_by_id(session_data['user_id'])
        if not user or not user.is_active:
            self._invalidate_session(session_data['id'])
            return None
        
        # Update last activity
        self._update_session_activity(session_data['id'])
        
        session_obj = self._row_to_session(session_data)
        return user, session_obj
    
    def invalidate_session(self, session_token: str) -> bool:
        """Invalidate a session."""
        rows = self.db.execute_query(
            "SELECT id FROM sessions WHERE session_token = ?", (session_token,)
        )
        
        if not rows:
            return False
        
        self._invalidate_session(rows[0]['id'])
        return True
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute_update(
            "UPDATE sessions SET is_active = FALSE WHERE expires_at < ? AND is_active = TRUE",
            (now,)
        )
    
    def _invalidate_session(self, session_id: str):
        """Mark session as inactive."""
        self.db.execute_update(
            "UPDATE sessions SET is_active = FALSE WHERE id = ?", (session_id,)
        )
    
    def _update_session_activity(self, session_id: str):
        """Update session last activity."""
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute_update(
            "UPDATE sessions SET last_activity = ? WHERE id = ?", (now, session_id)
        )
    
    def _row_to_session(self, row) -> Session:
        """Convert database row to Session object."""
        return Session(
            id=row['id'],
            user_id=row['user_id'],
            session_token=row['session_token'],
            ip_address=row['ip_address'],
            user_agent=row['user_agent'],
            created_at=row['created_at'],
            expires_at=row['expires_at'],
            is_active=bool(row['is_active']),
            last_activity=row['last_activity']
        )

class AuthEventManager:
    """Authentication event logging."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def log_event(self, event_type: str, user_id: Optional[str], success: bool, 
                  details: Dict[str, Any], session_id: Optional[str] = None):
        """Log an authentication event."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        self.db.execute_update('''
            INSERT INTO auth_events (id, timestamp, event_type, user_id, ip_address, 
                                   user_agent, success, details, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (event_id, timestamp, event_type, user_id, request.remote_addr,
              request.headers.get('User-Agent', ''), success, json.dumps(details), session_id))
    
    def get_user_events(self, user_id: str, limit: int = 100) -> List[AuthEvent]:
        """Get authentication events for a user."""
        rows = self.db.execute_query(
            "SELECT * FROM auth_events WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
            (user_id, limit)
        )
        
        return [self._row_to_auth_event(row) for row in rows]
    
    def get_recent_events(self, limit: int = 100) -> List[AuthEvent]:
        """Get recent authentication events."""
        rows = self.db.execute_query(
            "SELECT * FROM auth_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        
        return [self._row_to_auth_event(row) for row in rows]
    
    def _row_to_auth_event(self, row) -> AuthEvent:
        """Convert database row to AuthEvent object."""
        return AuthEvent(
            id=row['id'],
            timestamp=row['timestamp'],
            event_type=row['event_type'],
            user_id=row['user_id'],
            ip_address=row['ip_address'],
            user_agent=row['user_agent'],
            success=bool(row['success']),
            details=json.loads(row['details']),
            session_id=row['session_id']
        )

class AuthenticationService:
    """Main authentication service."""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.user_manager = UserManager(self.db_manager)
        self.api_key_manager = ApiKeyManager(self.db_manager)
        self.session_manager = SessionManager(self.db_manager)
        self.event_manager = AuthEventManager(self.db_manager)
    
    def authenticate_request(self) -> Optional[User]:
        """Authenticate the current request and return user if authenticated."""
        # Check for API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            result = self.api_key_manager.validate_api_key(api_key)
            if result:
                user, permissions = result
                g.current_user = user
                g.current_permissions = permissions
                return user
        
        # Check for session token
        session_token = request.headers.get('X-Session-Token') or session.get('session_token')
        if session_token:
            result = self.session_manager.validate_session(session_token)
            if result:
                user, session_obj = result
                g.current_user = user
                g.current_session = session_obj
                g.current_permissions = ROLE_PERMISSIONS.get(user.role, [])
                return user
        
        return None
    
    def require_auth(self, permissions: List[Permission] = None):
        """Decorator to require authentication and optional permissions."""
        def decorator(f):
            def wrapper(*args, **kwargs):
                user = self.authenticate_request()
                if not user:
                    raise AuthenticationError("Authentication required")
                
                if permissions:
                    user_permissions = getattr(g, 'current_permissions', [])
                    if not all(perm in user_permissions for perm in permissions):
                        raise AuthorizationError("Insufficient permissions")
                
                return f(*args, **kwargs)
            return wrapper
        return decorator
    
    def create_admin_user(self, username: str, email: str, password: str) -> User:
        """Create an admin user (for initial setup)."""
        return self.user_manager.create_user(username, email, password, UserRole.ADMIN)
    
    def get_current_user(self) -> Optional[User]:
        """Get the current authenticated user."""
        return getattr(g, 'current_user', None)
    
    def get_current_permissions(self) -> List[Permission]:
        """Get the current user's permissions."""
        return getattr(g, 'current_permissions', [])
    
    def logout(self, session_token: str = None):
        """Logout the current user."""
        if session_token:
            self.session_manager.invalidate_session(session_token)
        elif 'session_token' in session:
            self.session_manager.invalidate_session(session['session_token'])
            session.pop('session_token', None)
    
    def cleanup_sessions(self):
        """Clean up expired sessions."""
        self.session_manager.cleanup_expired_sessions()

# Global authentication service instance
auth_service = AuthenticationService()

# Flask integration
def init_auth(app):
    """Initialize authentication with Flask app."""
    @app.before_request
    def before_request():
        """Authenticate request before processing."""
        if AUTH_CONFIG['authentication_required']:
            auth_service.authenticate_request()
    
    @app.after_request
    def after_request(response):
        """Clean up after request."""
        # Clean up sessions periodically
        if hasattr(g, 'cleanup_sessions') and g.cleanup_sessions:
            auth_service.cleanup_sessions()
        return response

# Management commands
def create_admin_command(username: str, email: str, password: str):
    """Command to create an admin user."""
    try:
        user = auth_service.create_admin_user(username, email, password)
        print(f"Admin user '{username}' created successfully")
        return user
    except Exception as e:
        print(f"Error creating admin user: {e}")
        return None

def list_users_command():
    """Command to list all users."""
    try:
        # This would need to be implemented in UserManager
        print("User listing functionality would be implemented here")
    except Exception as e:
        print(f"Error listing users: {e}")

def reset_password_command(username: str, new_password: str):
    """Command to reset a user's password."""
    try:
        user = auth_service.user_manager.get_user_by_username(username)
        if not user:
            print(f"User '{username}' not found")
            return False
        
        # This would need to be implemented in UserManager
        print(f"Password reset functionality would be implemented here")
        return True
    except Exception as e:
        print(f"Error resetting password: {e}")
        return False