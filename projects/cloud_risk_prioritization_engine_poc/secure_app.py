"""
Secure Flask Application for Cloud Risk Prioritization Engine

This module implements security best practices including:
- User authentication with Flask-Login
- Input validation with marshmallow
- Secure session configuration
- Rate limiting
- Security headers
- Proper error handling
- CSRF protection
"""

import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, ValidationError, validate
import structlog

from src.database import db, get_database_url, init_db
from src.risk_engine import RiskPrioritizationService
from src.data_loader import DataLoader

# Configure secure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.iso_time_stamp,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


# Input validation schemas
class VulnerabilityQuerySchema(Schema):
    limit = fields.Integer(missing=50, validate=validate.Range(min=1, max=1000))
    source = fields.String(validate=validate.Length(max=100))
    publicly_accessible = fields.Boolean()


class RiskQuerySchema(Schema):
    limit = fields.Integer(missing=50, validate=validate.Range(min=1, max=1000))
    min_score = fields.Float(validate=validate.Range(min=0.0, max=100.0))
    business_tier = fields.String(validate=validate.OneOf([
        "Tier 0: Mission Critical",
        "Tier 1: High", 
        "Tier 2: Medium",
        "Tier 3: Low"
    ]))


class AssetQuerySchema(Schema):
    limit = fields.Integer(missing=50, validate=validate.Range(min=1, max=1000))
    business_tier = fields.String(validate=validate.OneOf([
        "Tier 0: Mission Critical",
        "Tier 1: High",
        "Tier 2: Medium", 
        "Tier 3: Low"
    ]))
    data_sensitivity = fields.String(validate=validate.OneOf([
        "PII", "Financial", "PHI", "Confidential", "Internal", "Public"
    ]))


# User model for authentication
class User(UserMixin, db.Model):
    """User model for authentication."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='viewer')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        """Set password with secure hashing."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash."""
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission):
        """Check if user has specific permission."""
        # Simple role-based permissions
        permissions = {
            'admin': ['view_vulnerabilities', 'modify_scores', 'manage_users'],
            'analyst': ['view_vulnerabilities', 'modify_scores'],
            'viewer': ['view_vulnerabilities']
        }
        return permission in permissions.get(self.role, [])


def require_permission(permission):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not current_user.has_permission(permission):
                logger.warning("Permission denied", 
                             user=current_user.username,
                             permission=permission,
                             endpoint=request.endpoint)
                return jsonify({'error': 'Permission denied'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_input(schema_class):
    """Decorator for input validation."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            schema = schema_class()
            try:
                # Validate query parameters
                validated_args = schema.load(request.args)
                request.validated_args = validated_args
                
                # Log access for audit
                logger.info("API access",
                           user=getattr(current_user, 'username', 'anonymous'),
                           endpoint=request.endpoint,
                           method=request.method,
                           validated_args=validated_args,
                           ip_address=request.remote_addr)
                
                return f(*args, **kwargs)
                
            except ValidationError as err:
                logger.warning("Input validation failed",
                              errors=err.messages,
                              endpoint=request.endpoint,
                              ip_address=request.remote_addr)
                return jsonify({'errors': err.messages}), 400
                
        return decorated_function
    return decorator


def create_secure_app(config=None):
    """
    Create and configure the secure Flask application.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured secure Flask application
    """
    app = Flask(__name__)
    
    # Security Configuration
    # Generate secure secret key if not provided
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key:
        logger.warning("No SECRET_KEY environment variable set. Generating temporary key.")
        secret_key = secrets.token_hex(32)
    
    app.config.update({
        'SECRET_KEY': secret_key,
        'SQLALCHEMY_DATABASE_URI': get_database_url(),
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        
        # Session Security
        'SESSION_COOKIE_SECURE': True,  # HTTPS only in production
        'SESSION_COOKIE_HTTPONLY': True,  # Prevent JS access
        'SESSION_COOKIE_SAMESITE': 'Lax',  # CSRF protection
        'PERMANENT_SESSION_LIFETIME': timedelta(hours=4),
        
        # Security Headers
        'SECURITY_HEADERS': True,
        
        # Rate Limiting
        'RATELIMIT_STORAGE_URL': 'memory://',
    })
    
    # Apply additional configuration
    if config:
        app.config.update(config)
    
    # Initialize security extensions
    
    # CORS with restricted origins (configure for production)
    allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5000').split(',')
    CORS(app, origins=allowed_origins, supports_credentials=True)
    
    # Security headers with Talisman
    csp = {
        'default-src': "'self'",
        'script-src': [
            "'self'", 
            "'unsafe-inline'",  # Required for Bootstrap
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ],
        'style-src': [
            "'self'", 
            "'unsafe-inline'",  # Required for Bootstrap
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ],
        'font-src': [
            "'self'",
            "https://cdnjs.cloudflare.com"
        ],
        'img-src': "'self' data:",
    }
    
    Talisman(app, 
             force_https=False,  # Set to True in production
             content_security_policy=csp)
    
    # Rate limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["1000 per hour"]
    )
    
    # Initialize database
    db.init_app(app)
    
    # Initialize authentication
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Initialize services
    risk_service = RiskPrioritizationService()
    
    # Error handlers with security logging
    @app.errorhandler(400)
    def bad_request(error):
        error_id = str(uuid.uuid4())
        logger.error("Bad request", 
                    error_id=error_id,
                    endpoint=request.endpoint,
                    method=request.method,
                    ip_address=request.remote_addr)
        return jsonify({
            'error': 'Bad request',
            'error_id': error_id
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        error_id = str(uuid.uuid4())
        logger.warning("Unauthorized access attempt",
                      error_id=error_id,
                      endpoint=request.endpoint,
                      ip_address=request.remote_addr)
        return jsonify({
            'error': 'Authentication required',
            'error_id': error_id
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        error_id = str(uuid.uuid4())
        logger.warning("Forbidden access attempt",
                      error_id=error_id,
                      user=getattr(current_user, 'username', 'anonymous'),
                      endpoint=request.endpoint,
                      ip_address=request.remote_addr)
        return jsonify({
            'error': 'Access forbidden',
            'error_id': error_id
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        error_id = str(uuid.uuid4())
        logger.info("Resource not found",
                   error_id=error_id,
                   endpoint=request.endpoint,
                   path=request.path,
                   ip_address=request.remote_addr)
        return jsonify({
            'error': 'Resource not found',
            'error_id': error_id
        }), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        error_id = str(uuid.uuid4())
        logger.warning("Rate limit exceeded",
                      error_id=error_id,
                      ip_address=request.remote_addr,
                      endpoint=request.endpoint)
        return jsonify({
            'error': 'Rate limit exceeded',
            'error_id': error_id,
            'retry_after': str(error.retry_after)
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        error_id = str(uuid.uuid4())
        logger.error("Internal server error",
                    error_id=error_id,
                    endpoint=request.endpoint,
                    method=request.method,
                    user=getattr(current_user, 'username', 'anonymous'),
                    ip_address=request.remote_addr,
                    exc_info=True)
        return jsonify({
            'error': 'Internal server error',
            'error_id': error_id
        }), 500
    
    # Authentication routes
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("10 per minute")
    def login():
        """User login."""
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Username and password are required', 'error')
                return render_template('login.html')
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password) and user.is_active:
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                logger.info("Successful login",
                           username=username,
                           ip_address=request.remote_addr)
                
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                logger.warning("Failed login attempt",
                              username=username,
                              ip_address=request.remote_addr)
                flash('Invalid username or password', 'error')
        
        return render_template('login.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        """User logout."""
        username = current_user.username
        logout_user()
        logger.info("User logout", username=username)
        flash('You have been logged out', 'info')
        return redirect(url_for('login'))
    
    # Main routes
    @app.route('/')
    @login_required
    def index():
        """Main dashboard page."""
        return render_template('index_secure.html')
    
    @app.route('/health')
    def health_check():
        """Health check endpoint."""
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'version': '1.0.0-secure',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error("Health check failed", error_id=error_id, exc_info=True)
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'error_id': error_id
            }), 500
    
    # API routes with security
    @app.route('/api/vulnerabilities')
    @login_required
    @require_permission('view_vulnerabilities')
    @validate_input(VulnerabilityQuerySchema)
    @limiter.limit("100 per minute")
    def get_vulnerabilities():
        """Get vulnerabilities with security and validation."""
        try:
            from src.database import Vulnerability
            
            args = request.validated_args
            
            # Build secure query
            query = Vulnerability.query
            
            # Apply validated filters
            if args.get('source'):
                query = query.filter(Vulnerability.source == args['source'])
            
            if args.get('publicly_accessible') is not None:
                query = query.filter(Vulnerability.publicly_accessible == args['publicly_accessible'])
            
            # Apply ordering and limit
            query = query.order_by(Vulnerability.cvss_base_severity.desc())
            query = query.limit(args['limit'])
            
            vulnerabilities = query.all()
            
            return jsonify({
                'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
                'total_count': len(vulnerabilities),
                'user': current_user.username,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error("Failed to retrieve vulnerabilities",
                        error_id=error_id,
                        user=current_user.username,
                        exc_info=True)
            return jsonify({
                'error': 'Failed to retrieve vulnerabilities',
                'error_id': error_id
            }), 500
    
    @app.route('/api/assets')
    @login_required
    @require_permission('view_vulnerabilities')
    @validate_input(AssetQuerySchema)
    @limiter.limit("100 per minute")
    def get_assets():
        """Get assets with security and validation."""
        try:
            from src.database import Asset
            
            args = request.validated_args
            
            # Build secure query
            query = Asset.query
            
            # Apply validated filters
            if args.get('business_tier'):
                query = query.filter(Asset.business_impact_tier == args['business_tier'])
            
            if args.get('data_sensitivity'):
                query = query.filter(Asset.data_sensitivity == args['data_sensitivity'])
            
            # Apply limit
            query = query.limit(args['limit'])
            
            assets = query.all()
            
            return jsonify({
                'assets': [asset.to_dict() for asset in assets],
                'total_count': len(assets),
                'user': current_user.username,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error("Failed to retrieve assets",
                        error_id=error_id,
                        user=current_user.username,
                        exc_info=True)
            return jsonify({
                'error': 'Failed to retrieve assets',
                'error_id': error_id
            }), 500
    
    @app.route('/api/prioritized-risks')
    @login_required
    @require_permission('view_vulnerabilities')
    @validate_input(RiskQuerySchema)
    @limiter.limit("50 per minute")
    def get_prioritized_risks():
        """Get prioritized risks with security."""
        try:
            args = request.validated_args
            
            # Get prioritized vulnerabilities
            prioritized_vulns = risk_service.get_prioritized_vulnerabilities()
            
            # Apply validated filters
            if args.get('min_score') is not None:
                prioritized_vulns = [
                    vuln for vuln in prioritized_vulns
                    if vuln.get('prioritized_risk_score', 0) >= args['min_score']
                ]
            
            if args.get('business_tier'):
                prioritized_vulns = [
                    vuln for vuln in prioritized_vulns
                    if vuln.get('asset_context', {}).get('business_impact_tier') == args['business_tier']
                ]
            
            # Apply limit
            prioritized_vulns = prioritized_vulns[:args['limit']]
            
            return jsonify({
                'prioritized_vulnerabilities': prioritized_vulns,
                'total_count': len(prioritized_vulns),
                'user': current_user.username,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error("Failed to retrieve prioritized risks",
                        error_id=error_id,
                        user=current_user.username,
                        exc_info=True)
            return jsonify({
                'error': 'Failed to retrieve prioritized risks',
                'error_id': error_id
            }), 500
    
    @app.route('/api/vulnerability/<string:vuln_id>')
    @login_required
    @require_permission('view_vulnerabilities')
    @limiter.limit("200 per minute")
    def get_vulnerability_details(vuln_id):
        """Get vulnerability details with security."""
        try:
            # Validate vuln_id format (basic protection)
            if not vuln_id or len(vuln_id) > 50:
                return jsonify({'error': 'Invalid vulnerability ID'}), 400
            
            from src.database import Vulnerability, Asset, RiskScore
            
            vulnerability = Vulnerability.query.filter_by(id=vuln_id).first()
            if not vulnerability:
                return jsonify({'error': 'Vulnerability not found'}), 404
            
            asset = Asset.query.filter_by(asset_id=vulnerability.asset_id).first()
            risk_score = RiskScore.query.filter_by(vulnerability_id=vuln_id).first()
            
            # Build secure response
            response = vulnerability.to_dict()
            
            if asset:
                response['asset_context'] = asset.to_dict()
            
            if risk_score:
                response['prioritized_risk_score'] = risk_score.calculated_score
                response['risk_calculation_factors'] = risk_score.calculation_factors
                response['risk_calculated_at'] = risk_score.calculated_at.isoformat()
            
            response['accessed_by'] = current_user.username
            response['access_timestamp'] = datetime.now(timezone.utc).isoformat()
            
            return jsonify(response)
            
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error("Failed to retrieve vulnerability details",
                        error_id=error_id,
                        vuln_id=vuln_id,
                        user=current_user.username,
                        exc_info=True)
            return jsonify({
                'error': 'Failed to retrieve vulnerability details',
                'error_id': error_id
            }), 500
    
    @app.route('/api/refresh-scores', methods=['POST'])
    @login_required
    @require_permission('modify_scores')
    @limiter.limit("5 per minute")
    def refresh_risk_scores():
        """Refresh risk scores with security."""
        try:
            logger.info("Risk score recalculation started",
                       user=current_user.username,
                       ip_address=request.remote_addr)
            
            results = risk_service.calculate_all_risk_scores()
            
            logger.info("Risk score recalculation completed",
                       user=current_user.username,
                       results=results)
            
            return jsonify({
                'status': 'success',
                'message': 'Risk scores recalculated successfully',
                'results': results,
                'user': current_user.username,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error("Failed to refresh risk scores",
                        error_id=error_id,
                        user=current_user.username,
                        exc_info=True)
            return jsonify({
                'status': 'error',
                'message': 'Failed to refresh risk scores',
                'error_id': error_id
            }), 500
    
    @app.route('/api/dashboard-stats')
    @login_required
    @require_permission('view_vulnerabilities')
    @limiter.limit("60 per minute")
    def get_dashboard_stats():
        """Get dashboard statistics with security."""
        try:
            stats = risk_service.get_risk_statistics()
            
            # Add source distribution
            from src.database import Vulnerability
            source_distribution = db.session.query(
                Vulnerability.source,
                db.func.count(Vulnerability.id)
            ).group_by(Vulnerability.source).all()
            
            stats['vulnerability_source_distribution'] = {
                source: count for source, count in source_distribution
            }
            
            # Add metadata
            stats['user'] = current_user.username
            stats['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            return jsonify(stats)
            
        except Exception as e:
            error_id = str(uuid.uuid4())
            logger.error("Failed to retrieve dashboard statistics",
                        error_id=error_id,
                        user=current_user.username,
                        exc_info=True)
            return jsonify({
                'error': 'Failed to retrieve dashboard statistics',
                'error_id': error_id
            }), 500
    
    return app


def create_default_user(app):
    """Create default admin user if none exists."""
    with app.app_context():
        if not User.query.first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            admin_user.set_password('admin123')  # Change in production!
            
            db.session.add(admin_user)
            db.session.commit()
            
            logger.info("Default admin user created",
                       username=admin_user.username)


# Application factory
def create_app(config=None):
    """Create the secure application."""
    return create_secure_app(config)


if __name__ == '__main__':
    app = create_secure_app()
    
    with app.app_context():
        # Initialize database
        db.create_all()
        
        # Create default user
        create_default_user(app)
        
        # Load sample data if needed
        loader = DataLoader()
        if not loader.check_data_exists():
            loader.load_sample_data()
    
    # Use secure settings for production
    app.run(
        debug=False,  # Never True in production
        host='127.0.0.1',  # Bind to localhost only
        port=5000,
        threaded=True
    )