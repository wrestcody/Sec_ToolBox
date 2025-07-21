"""
Okta Integration
Secure LLM Interaction Proxy

Provides integration with Okta for:
- Single Sign-On (SSO) authentication
- User provisioning and deprovisioning
- Multi-factor authentication (MFA)
- Group-based access control
- Identity verification
- SAML/OAuth2 integration
"""

import os
import json
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import jwt
from jwt.algorithms import RSAAlgorithm

class OktaIntegrationError(Exception):
    """Custom exception for Okta integration errors."""
    pass

class OktaAuthType(Enum):
    """Okta authentication types."""
    SSO = "sso"
    OAUTH2 = "oauth2"
    SAML = "saml"
    API_TOKEN = "api_token"

@dataclass
class OktaConfig:
    """Okta configuration settings."""
    org_url: str
    api_token: str
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    auth_type: OktaAuthType = OktaAuthType.API_TOKEN
    enable_sso: bool = True
    enable_mfa: bool = True
    enable_user_provisioning: bool = True
    enable_group_sync: bool = True
    session_timeout_minutes: int = 60
    verify_ssl: bool = True

@dataclass
class OktaUser:
    """Okta user information."""
    id: str
    username: str
    email: str
    first_name: str
    last_name: str
    status: str
    created: str
    last_login: Optional[str]
    groups: List[str]
    mfa_enabled: bool
    profile: Dict[str, Any]

@dataclass
class OktaGroup:
    """Okta group information."""
    id: str
    name: str
    description: str
    type: str
    created: str
    last_updated: str
    member_count: int

@dataclass
class OktaSession:
    """Okta session information."""
    id: str
    user_id: str
    login: str
    created: str
    expires_at: str
    status: str
    last_factor_verification: Optional[str]

class OktaIntegration:
    """Okta integration for enterprise SSO and identity management."""
    
    def __init__(self, config: OktaConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'SSWS {config.api_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Verify SSL
        if not config.verify_ssl:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Base URL
        self.base_url = config.org_url.rstrip('/')
        
        # Cache for JWKS
        self._jwks_cache = None
        self._jwks_cache_time = None
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None, 
                     params: Dict = None) -> Dict:
        """Make HTTP request to Okta API."""
        url = f"{self.base_url}/api/v1{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params
            )
            response.raise_for_status()
            
            if response.content:
                return response.json()
            return {}
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Okta API request failed: {e}")
            raise OktaIntegrationError(f"Okta API request failed: {e}")
    
    # User Management
    def get_user(self, user_id: str) -> Optional[OktaUser]:
        """Get user by ID."""
        try:
            response = self._make_request('GET', f'/users/{user_id}')
            
            # Get user groups
            groups_response = self._make_request('GET', f'/users/{user_id}/groups')
            groups = [group['id'] for group in groups_response]
            
            # Check MFA status
            mfa_response = self._make_request('GET', f'/users/{user_id}/factors')
            mfa_enabled = len(mfa_response) > 0
            
            return OktaUser(
                id=response['id'],
                username=response['profile']['login'],
                email=response['profile']['email'],
                first_name=response['profile']['firstName'],
                last_name=response['profile']['lastName'],
                status=response['status'],
                created=response['created'],
                last_login=response.get('lastLogin'),
                groups=groups,
                mfa_enabled=mfa_enabled,
                profile=response['profile']
            )
            
        except OktaIntegrationError:
            return None
    
    def get_user_by_email(self, email: str) -> Optional[OktaUser]:
        """Get user by email address."""
        try:
            response = self._make_request('GET', '/users', params={'q': email})
            
            if response:
                user_data = response[0]
                return self.get_user(user_data['id'])
            
            return None
            
        except OktaIntegrationError:
            return None
    
    def create_user(self, user_data: Dict) -> OktaUser:
        """Create a new user in Okta."""
        try:
            # Prepare user profile
            profile = {
                'firstName': user_data['first_name'],
                'lastName': user_data['last_name'],
                'email': user_data['email'],
                'login': user_data['email']
            }
            
            # Add additional profile fields
            if 'department' in user_data:
                profile['department'] = user_data['department']
            if 'title' in user_data:
                profile['title'] = user_data['title']
            
            user_payload = {
                'profile': profile,
                'credentials': {
                    'password': {
                        'value': user_data['password']
                    }
                }
            }
            
            # Set activation if provided
            if user_data.get('activate', True):
                user_payload['activate'] = True
            
            response = self._make_request('POST', '/users', data=user_payload)
            
            # Add user to groups if specified
            if 'groups' in user_data:
                for group_id in user_data['groups']:
                    self.add_user_to_group(response['id'], group_id)
            
            return self.get_user(response['id'])
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to create user: {e}")
            raise
    
    def update_user(self, user_id: str, user_data: Dict) -> OktaUser:
        """Update user information."""
        try:
            # Prepare update payload
            update_payload = {}
            
            if 'profile' in user_data:
                update_payload['profile'] = user_data['profile']
            
            if 'credentials' in user_data:
                update_payload['credentials'] = user_data['credentials']
            
            self._make_request('PUT', f'/users/{user_id}', data=update_payload)
            
            return self.get_user(user_id)
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to update user: {e}")
            raise
    
    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate a user."""
        try:
            self._make_request('POST', f'/users/{user_id}/lifecycle/deactivate')
            self.logger.info(f"User {user_id} deactivated successfully")
            return True
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to deactivate user: {e}")
            return False
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        try:
            self._make_request('DELETE', f'/users/{user_id}')
            self.logger.info(f"User {user_id} deleted successfully")
            return True
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to delete user: {e}")
            return False
    
    def list_users(self, limit: int = 200, search: str = None) -> List[OktaUser]:
        """List users with optional search."""
        try:
            params = {'limit': limit}
            if search:
                params['q'] = search
            
            response = self._make_request('GET', '/users', params=params)
            
            users = []
            for user_data in response:
                user = self.get_user(user_data['id'])
                if user:
                    users.append(user)
            
            return users
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to list users: {e}")
            return []
    
    # Group Management
    def get_group(self, group_id: str) -> Optional[OktaGroup]:
        """Get group by ID."""
        try:
            response = self._make_request('GET', f'/groups/{group_id}')
            
            return OktaGroup(
                id=response['id'],
                name=response['profile']['name'],
                description=response['profile'].get('description', ''),
                type=response['type'],
                created=response['created'],
                last_updated=response['lastUpdated'],
                member_count=response.get('objectClass', [])
            )
            
        except OktaIntegrationError:
            return None
    
    def create_group(self, name: str, description: str = None) -> OktaGroup:
        """Create a new group."""
        try:
            group_data = {
                'profile': {
                    'name': name,
                    'description': description or f"Group for Secure LLM Proxy - {name}"
                }
            }
            
            response = self._make_request('POST', '/groups', data=group_data)
            
            return self.get_group(response['id'])
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to create group: {e}")
            raise
    
    def add_user_to_group(self, user_id: str, group_id: str) -> bool:
        """Add user to group."""
        try:
            self._make_request('PUT', f'/groups/{group_id}/users/{user_id}')
            self.logger.info(f"User {user_id} added to group {group_id}")
            return True
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to add user to group: {e}")
            return False
    
    def remove_user_from_group(self, user_id: str, group_id: str) -> bool:
        """Remove user from group."""
        try:
            self._make_request('DELETE', f'/groups/{group_id}/users/{user_id}')
            self.logger.info(f"User {user_id} removed from group {group_id}")
            return True
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to remove user from group: {e}")
            return False
    
    def list_groups(self, limit: int = 200, search: str = None) -> List[OktaGroup]:
        """List groups with optional search."""
        try:
            params = {'limit': limit}
            if search:
                params['q'] = search
            
            response = self._make_request('GET', '/groups', params=params)
            
            groups = []
            for group_data in response:
                group = self.get_group(group_data['id'])
                if group:
                    groups.append(group)
            
            return groups
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to list groups: {e}")
            return []
    
    # Authentication and SSO
    def authenticate_user(self, username: str, password: str, 
                         mfa_code: str = None) -> Optional[Dict]:
        """Authenticate user with Okta."""
        try:
            # Primary authentication
            auth_data = {
                'username': username,
                'password': password,
                'options': {
                    'multiOptionalFactorEnroll': False,
                    'warnBeforePasswordExpired': True
                }
            }
            
            response = self._make_request('POST', '/authn', data=auth_data)
            
            # Handle MFA if required
            if response['status'] == 'MFA_REQUIRED':
                if not mfa_code:
                    raise OktaIntegrationError("MFA code required")
                
                # Get factor ID
                factor_id = response['_embedded']['factors'][0]['id']
                
                # Verify MFA
                mfa_data = {
                    'stateToken': response['stateToken'],
                    'passCode': mfa_code
                }
                
                mfa_response = self._make_request('POST', f'/authn/factors/{factor_id}/verify', data=mfa_data)
                
                if mfa_response['status'] == 'SUCCESS':
                    return mfa_response
            
            elif response['status'] == 'SUCCESS':
                return response
            
            return None
            
        except OktaIntegrationError as e:
            self.logger.error(f"Authentication failed: {e}")
            return None
    
    def create_session(self, user_id: str, session_token: str) -> Optional[OktaSession]:
        """Create a session for a user."""
        try:
            session_data = {
                'sessionToken': session_token
            }
            
            response = self._make_request('POST', '/sessions', data=session_data)
            
            return OktaSession(
                id=response['id'],
                user_id=response['userId'],
                login=response['login'],
                created=response['createdAt'],
                expires_at=response['expiresAt'],
                status=response['status'],
                last_factor_verification=response.get('lastFactorVerification')
            )
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to create session: {e}")
            return None
    
    def get_session(self, session_id: str) -> Optional[OktaSession]:
        """Get session by ID."""
        try:
            response = self._make_request('GET', f'/sessions/{session_id}')
            
            return OktaSession(
                id=response['id'],
                user_id=response['userId'],
                login=response['login'],
                created=response['createdAt'],
                expires_at=response['expiresAt'],
                status=response['status'],
                last_factor_verification=response.get('lastFactorVerification')
            )
            
        except OktaIntegrationError:
            return None
    
    def end_session(self, session_id: str) -> bool:
        """End a session."""
        try:
            self._make_request('DELETE', f'/sessions/{session_id}')
            self.logger.info(f"Session {session_id} ended successfully")
            return True
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to end session: {e}")
            return False
    
    # OAuth2 Integration
    def get_authorization_url(self, state: str = None, scope: str = "openid profile email") -> str:
        """Get OAuth2 authorization URL."""
        if not self.config.client_id:
            raise OktaIntegrationError("OAuth2 client_id not configured")
        
        params = {
            'client_id': self.config.client_id,
            'response_type': 'code',
            'scope': scope,
            'redirect_uri': self.config.redirect_uri,
            'state': state or 'secure_llm_proxy'
        }
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{self.base_url}/oauth2/v1/authorize?{query_string}"
    
    def exchange_code_for_token(self, code: str) -> Dict:
        """Exchange authorization code for access token."""
        if not self.config.client_secret:
            raise OktaIntegrationError("OAuth2 client_secret not configured")
        
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/oauth2/v1/token",
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Token exchange failed: {e}")
            raise OktaIntegrationError(f"Token exchange failed: {e}")
    
    def get_user_info(self, access_token: str) -> Dict:
        """Get user information using access token."""
        try:
            response = requests.get(
                f"{self.base_url}/oauth2/v1/userinfo",
                headers={'Authorization': f'Bearer {access_token}'}
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get user info: {e}")
            raise OktaIntegrationError(f"Failed to get user info: {e}")
    
    # JWT Token Validation
    def _get_jwks(self) -> Dict:
        """Get JSON Web Key Set from Okta."""
        # Check cache
        if (self._jwks_cache and self._jwks_cache_time and 
            datetime.now(timezone.utc) - self._jwks_cache_time < timedelta(hours=1)):
            return self._jwks_cache
        
        try:
            response = requests.get(f"{self.base_url}/oauth2/v1/keys")
            response.raise_for_status()
            
            self._jwks_cache = response.json()
            self._jwks_cache_time = datetime.now(timezone.utc)
            
            return self._jwks_cache
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get JWKS: {e}")
            raise OktaIntegrationError(f"Failed to get JWKS: {e}")
    
    def validate_jwt_token(self, token: str, audience: str = None) -> Dict:
        """Validate JWT token from Okta."""
        try:
            # Decode header to get key ID
            header = jwt.get_unverified_header(token)
            key_id = header['kid']
            
            # Get JWKS
            jwks = self._get_jwks()
            
            # Find the key
            public_key = None
            for key in jwks['keys']:
                if key['kid'] == key_id:
                    public_key = RSAAlgorithm.from_jwk(json.dumps(key))
                    break
            
            if not public_key:
                raise OktaIntegrationError("Public key not found")
            
            # Validate token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=audience or self.config.client_id,
                issuer=f"{self.base_url}/oauth2/default"
            )
            
            return payload
            
        except jwt.InvalidTokenError as e:
            self.logger.error(f"JWT validation failed: {e}")
            raise OktaIntegrationError(f"JWT validation failed: {e}")
    
    # MFA Management
    def enroll_mfa_factor(self, user_id: str, factor_type: str = "token:software:totp") -> Dict:
        """Enroll MFA factor for user."""
        try:
            factor_data = {
                'factorType': factor_type,
                'provider': 'OKTA'
            }
            
            response = self._make_request('POST', f'/users/{user_id}/factors', data=factor_data)
            
            self.logger.info(f"MFA factor enrolled for user {user_id}")
            return response
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to enroll MFA factor: {e}")
            raise
    
    def verify_mfa_factor(self, user_id: str, factor_id: str, pass_code: str) -> bool:
        """Verify MFA factor."""
        try:
            verify_data = {
                'passCode': pass_code
            }
            
            response = self._make_request('POST', f'/users/{user_id}/factors/{factor_id}/verify', data=verify_data)
            
            if response['status'] == 'VERIFIED':
                self.logger.info(f"MFA factor verified for user {user_id}")
                return True
            
            return False
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to verify MFA factor: {e}")
            return False
    
    def list_mfa_factors(self, user_id: str) -> List[Dict]:
        """List MFA factors for user."""
        try:
            response = self._make_request('GET', f'/users/{user_id}/factors')
            return response
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to list MFA factors: {e}")
            return []
    
    # Application Management
    def get_applications(self, limit: int = 200) -> List[Dict]:
        """List applications."""
        try:
            response = self._make_request('GET', '/apps', params={'limit': limit})
            return response
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to list applications: {e}")
            return []
    
    def assign_user_to_app(self, user_id: str, app_id: str) -> bool:
        """Assign user to application."""
        try:
            assignment_data = {
                'id': app_id
            }
            
            self._make_request('POST', f'/apps/{app_id}/users', data=assignment_data)
            self.logger.info(f"User {user_id} assigned to app {app_id}")
            return True
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to assign user to app: {e}")
            return False
    
    # Logs and Events
    def get_system_logs(self, since: str = None, until: str = None, 
                       limit: int = 100) -> List[Dict]:
        """Get system logs."""
        try:
            params = {'limit': limit}
            
            if since:
                params['since'] = since
            if until:
                params['until'] = until
            
            response = self._make_request('GET', '/logs', params=params)
            return response
            
        except OktaIntegrationError as e:
            self.logger.error(f"Failed to get system logs: {e}")
            return []
    
    # Health Check
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of Okta integration."""
        health_status = {
            'overall_status': 'healthy',
            'services': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Check API connectivity
        try:
            self._make_request('GET', '/users', params={'limit': 1})
            health_status['services']['api'] = 'healthy'
        except Exception as e:
            health_status['services']['api'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        # Check OAuth2 configuration
        if self.config.client_id and self.config.client_secret:
            try:
                self._get_jwks()
                health_status['services']['oauth2'] = 'healthy'
            except Exception as e:
                health_status['services']['oauth2'] = f'unhealthy: {str(e)}'
                health_status['overall_status'] = 'unhealthy'
        else:
            health_status['services']['oauth2'] = 'not_configured'
        
        return health_status