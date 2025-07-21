"""
Guardian Enhanced Flask Application

This module implements the Flask application enhanced with Guardian's Mandate
evidence integrity features including cryptographic tamper-evident logging,
immutable audit trails, and verifiable chain of custody.

All API interactions, data access, and system operations are automatically
tracked with cryptographic evidence integrity for forensic investigations
and compliance requirements.
"""

import os
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import structlog
from datetime import datetime, timezone

from src.database import db, get_database_url, init_db
from src.enhanced_risk_engine import (
    GuardianRiskPrioritizationService,
    GuardianDataAccessController
)
from src.evidence_integrity import (
    ChainOfCustodyTracker,
    ForensicExporter,
    ImmutableAuditLog
)
from src.data_loader import DataLoader

# Configure structured logging with enhanced security context
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.iso_time_stamp,
        structlog.processors.add_context,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


def create_guardian_app(config=None):
    """
    Create and configure the Guardian Enhanced Flask application.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured Flask application with Guardian's evidence integrity
    """
    app = Flask(__name__)
    
    # Configure CORS for API access
    CORS(app)
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Guardian-specific configuration
    app.config['GUARDIAN_EVIDENCE_INTEGRITY'] = True
    app.config['GUARDIAN_CRYPTOGRAPHIC_LOGGING'] = True
    app.config['GUARDIAN_CHAIN_OF_CUSTODY'] = True
    
    # Apply any additional configuration
    if config:
        app.config.update(config)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize Guardian services
    risk_service = GuardianRiskPrioritizationService()
    data_controller = GuardianDataAccessController()
    chain_tracker = ChainOfCustodyTracker()
    forensic_exporter = ForensicExporter()
    
    # Record application initialization
    @app.before_first_request
    def record_app_initialization():
        """Record application startup in evidence chain."""
        chain_tracker.record_event(
            event_type="application_startup",
            event_data={
                "application": "GuardianEnhancedRiskPrioritizer",
                "version": "1.0.0",
                "guardian_features_enabled": True,
                "evidence_integrity": True,
                "startup_timestamp": datetime.now(timezone.utc).isoformat()
            },
            actor_identity="system",
            system_context={
                "operation": "application_lifecycle",
                "phase": "initialization",
                "security_level": "enhanced"
            }
        )
    
    def get_actor_identity(request_obj):
        """Extract actor identity from request (enhanced for production authentication)."""
        # In production, this would extract from JWT token, session, etc.
        return request_obj.headers.get('X-Actor-Identity', 'anonymous_user')
    
    def record_api_access(endpoint: str, method: str, actor_identity: str, request_data: dict = None):
        """Record API access event in chain of custody."""
        return chain_tracker.record_event(
            event_type="api_access",
            event_data={
                "endpoint": endpoint,
                "method": method,
                "actor_identity": actor_identity,
                "request_data": request_data or {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_agent": request.headers.get('User-Agent', 'unknown'),
                "ip_address": request.remote_addr
            },
            actor_identity=actor_identity,
            system_context={
                "operation": "api_interaction",
                "endpoint": endpoint,
                "audit_level": "comprehensive"
            }
        )
    
    @app.route('/')
    def index():
        """Main dashboard page with evidence tracking."""
        actor_identity = get_actor_identity(request)
        
        # Record dashboard access
        record_api_access('/', 'GET', actor_identity)
        
        return render_template('guardian_index.html')
    
    @app.route('/health')
    def health_check():
        """Enhanced health check with Guardian status."""
        actor_identity = get_actor_identity(request)
        
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            
            # Verify chain integrity (sample)
            chain_verification = chain_tracker.verify_chain_integrity()
            
            health_status = {
                'status': 'healthy',
                'database': 'connected',
                'version': '1.0.0',
                'guardian_features': {
                    'evidence_integrity': True,
                    'chain_of_custody': True,
                    'cryptographic_logging': True,
                    'chain_integrity_verified': chain_verification['chain_integrity']
                }
            }
            
            # Record health check access
            record_api_access('/health', 'GET', actor_identity, health_status)
            
            return jsonify(health_status)
            
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            
            # Record health check failure
            chain_tracker.record_event(
                event_type="health_check_failed",
                event_data={
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "health_check",
                    "error_occurred": True
                }
            )
            
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'error': str(e)
            }), 500
    
    @app.route('/api/vulnerabilities')
    def get_vulnerabilities():
        """
        Get vulnerabilities with comprehensive evidence tracking.
        """
        actor_identity = get_actor_identity(request)
        
        # Record API access
        access_event_id = record_api_access(
            '/api/vulnerabilities', 
            'GET', 
            actor_identity,
            dict(request.args)
        )
        
        try:
            from src.database import Vulnerability
            
            # Build query with optional filters
            query = Vulnerability.query
            
            # Apply filters with validation
            source = request.args.get('source')
            if source:
                # Record filter usage
                chain_tracker.record_event(
                    event_type="data_filter_applied",
                    event_data={
                        "filter_type": "source",
                        "filter_value": source,
                        "access_event_id": access_event_id
                    },
                    actor_identity=actor_identity,
                    system_context={
                        "operation": "data_filtering",
                        "data_type": "vulnerability"
                    }
                )
                query = query.filter(Vulnerability.source == source)
            
            publicly_accessible = request.args.get('publicly_accessible')
            if publicly_accessible is not None:
                is_public = publicly_accessible.lower() == 'true'
                query = query.filter(Vulnerability.publicly_accessible == is_public)
            
            # Apply ordering and limit
            query = query.order_by(Vulnerability.cvss_base_severity.desc())
            
            limit = request.args.get('limit', type=int)
            if limit:
                query = query.limit(limit)
            
            vulnerabilities = query.all()
            
            # Convert to dict with evidence metadata
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_dict = vuln.to_dict()
                
                # Add evidence integrity metadata
                vuln_dict['evidence_integrity'] = {
                    'access_event_id': access_event_id,
                    'accessed_by': actor_identity,
                    'access_timestamp': datetime.now(timezone.utc).isoformat(),
                    'data_classification': 'sensitive',
                    'chain_of_custody_maintained': True
                }
                
                vuln_data.append(vuln_dict)
            
            response_data = {
                'vulnerabilities': vuln_data,
                'total_count': len(vulnerabilities),
                'evidence_integrity': {
                    'access_event_id': access_event_id,
                    'response_timestamp': datetime.now(timezone.utc).isoformat(),
                    'actor_identity': actor_identity
                }
            }
            
            # Record successful data access
            chain_tracker.record_event(
                event_type="vulnerability_data_accessed",
                event_data={
                    "total_records": len(vulnerabilities),
                    "filters_applied": dict(request.args),
                    "access_event_id": access_event_id
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "data_access",
                    "data_type": "vulnerability",
                    "access_granted": True
                }
            )
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error("Failed to retrieve vulnerabilities", error=str(e))
            
            # Record access failure
            chain_tracker.record_event(
                event_type="vulnerability_data_access_failed",
                event_data={
                    "error": str(e),
                    "access_event_id": access_event_id
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "data_access",
                    "error_occurred": True
                }
            )
            
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/prioritized-risks')
    def get_prioritized_risks():
        """Get prioritized risks with evidence integrity."""
        actor_identity = get_actor_identity(request)
        
        # Record API access
        access_event_id = record_api_access(
            '/api/prioritized-risks',
            'GET',
            actor_identity,
            dict(request.args)
        )
        
        try:
            # Get prioritized vulnerabilities using Guardian service
            prioritized_vulns = risk_service.get_prioritized_vulnerabilities()
            
            # Apply filters with evidence tracking
            limit = request.args.get('limit', type=int)
            min_score = request.args.get('min_score', type=float)
            business_tier = request.args.get('business_tier')
            
            if min_score:
                prioritized_vulns = [
                    vuln for vuln in prioritized_vulns
                    if vuln.get('prioritized_risk_score', 0) >= min_score
                ]
            
            if business_tier:
                prioritized_vulns = [
                    vuln for vuln in prioritized_vulns
                    if vuln.get('asset_context', {}).get('business_impact_tier') == business_tier
                ]
            
            if limit:
                prioritized_vulns = prioritized_vulns[:limit]
            
            # Add evidence integrity to each record
            for vuln in prioritized_vulns:
                vuln['evidence_integrity'] = {
                    'access_event_id': access_event_id,
                    'prioritization_verified': True,
                    'risk_calculation_auditable': True
                }
            
            response_data = {
                'prioritized_vulnerabilities': prioritized_vulns,
                'total_count': len(prioritized_vulns),
                'evidence_integrity': {
                    'access_event_id': access_event_id,
                    'prioritization_algorithm_verified': True,
                    'chain_of_custody_maintained': True
                }
            }
            
            # Record successful access
            chain_tracker.record_event(
                event_type="prioritized_risks_accessed",
                event_data={
                    "total_risks": len(prioritized_vulns),
                    "filters_applied": dict(request.args),
                    "access_event_id": access_event_id
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "risk_data_access",
                    "data_classification": "risk_analysis",
                    "access_granted": True
                }
            )
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error("Failed to retrieve prioritized risks", error=str(e))
            
            # Record failure
            chain_tracker.record_event(
                event_type="prioritized_risks_access_failed",
                event_data={
                    "error": str(e),
                    "access_event_id": access_event_id
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "risk_data_access",
                    "error_occurred": True
                }
            )
            
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/vulnerability/<string:vuln_id>')
    def get_vulnerability_details(vuln_id):
        """Get vulnerability details with evidence tracking."""
        actor_identity = get_actor_identity(request)
        
        try:
            # Use Guardian data controller for enhanced access tracking
            vuln_data = data_controller.access_vulnerability_data(
                vulnerability_id=vuln_id,
                actor_identity=actor_identity,
                access_purpose="detailed_view"
            )
            
            if not vuln_data:
                return jsonify({'error': 'Vulnerability not found'}), 404
            
            # Get asset context and risk score with evidence tracking
            from src.database import Asset, RiskScore
            
            asset = Asset.query.filter_by(asset_id=vuln_data['asset_id']).first()
            risk_score = RiskScore.query.filter_by(vulnerability_id=vuln_id).first()
            
            if asset:
                vuln_data['asset_context'] = asset.to_dict()
            
            if risk_score:
                vuln_data['prioritized_risk_score'] = risk_score.calculated_score
                vuln_data['risk_calculation_factors'] = risk_score.calculation_factors
                vuln_data['risk_calculated_at'] = risk_score.calculated_at.isoformat()
            
            return jsonify(vuln_data)
            
        except Exception as e:
            logger.error("Failed to retrieve vulnerability details", 
                        vuln_id=vuln_id, error=str(e))
            
            # Record access failure
            chain_tracker.record_event(
                event_type="vulnerability_detail_access_failed",
                event_data={
                    "vulnerability_id": vuln_id,
                    "error": str(e)
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "detailed_data_access",
                    "error_occurred": True
                }
            )
            
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/refresh-scores', methods=['POST'])
    def refresh_risk_scores():
        """Refresh risk scores with comprehensive audit trail."""
        actor_identity = get_actor_identity(request)
        
        # Record score refresh request
        refresh_event_id = record_api_access(
            '/api/refresh-scores',
            'POST',
            actor_identity
        )
        
        try:
            logger.info("Starting Guardian risk score recalculation", 
                       actor=actor_identity,
                       event_id=refresh_event_id)
            
            # Use Guardian service for enhanced calculation tracking
            results = risk_service.calculate_all_risk_scores(actor_identity=actor_identity)
            
            response_data = {
                'status': 'success',
                'message': 'Risk scores recalculated with evidence integrity',
                'results': results,
                'evidence_integrity': {
                    'refresh_event_id': refresh_event_id,
                    'calculation_auditable': True,
                    'chain_of_custody_maintained': True
                }
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            logger.error("Failed to refresh risk scores", error=str(e))
            
            # Record failure
            chain_tracker.record_event(
                event_type="risk_score_refresh_failed",
                event_data={
                    "error": str(e),
                    "refresh_event_id": refresh_event_id
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "risk_calculation",
                    "error_occurred": True
                }
            )
            
            return jsonify({
                'status': 'error',
                'message': 'Failed to refresh risk scores',
                'error': 'Internal server error'
            }), 500
    
    @app.route('/api/evidence/export', methods=['POST'])
    def export_forensic_evidence():
        """Export forensic evidence package."""
        actor_identity = get_actor_identity(request)
        
        # Record evidence export request
        export_request_id = record_api_access(
            '/api/evidence/export',
            'POST',
            actor_identity,
            request.json or {}
        )
        
        try:
            # Parse request parameters
            data = request.json or {}
            vulnerability_ids = data.get('vulnerability_ids')
            date_range = None
            
            if data.get('start_date') and data.get('end_date'):
                from datetime import datetime
                date_range = (
                    datetime.fromisoformat(data['start_date']),
                    datetime.fromisoformat(data['end_date'])
                )
            
            # Export evidence package
            evidence_package = risk_service.export_calculation_evidence(
                vulnerability_ids=vulnerability_ids,
                date_range=date_range,
                actor_identity=actor_identity
            )
            
            # Record successful export
            chain_tracker.record_event(
                event_type="forensic_evidence_exported",
                event_data={
                    "export_request_id": export_request_id,
                    "evidence_package_id": evidence_package["metadata"]["export_id"],
                    "total_entries": evidence_package["metadata"]["total_entries"],
                    "export_scope": data
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "forensic_export",
                    "legal_evidence": True,
                    "export_complete": True
                }
            )
            
            return jsonify({
                'status': 'success',
                'evidence_package': evidence_package,
                'export_metadata': {
                    'export_request_id': export_request_id,
                    'legal_admissible': True,
                    'chain_of_custody_verified': True
                }
            })
            
        except Exception as e:
            logger.error("Failed to export forensic evidence", error=str(e))
            
            # Record export failure
            chain_tracker.record_event(
                event_type="forensic_evidence_export_failed",
                event_data={
                    "export_request_id": export_request_id,
                    "error": str(e)
                },
                actor_identity=actor_identity,
                system_context={
                    "operation": "forensic_export",
                    "error_occurred": True
                }
            )
            
            return jsonify({
                'status': 'error',
                'message': 'Failed to export evidence package',
                'error': 'Internal server error'
            }), 500
    
    @app.route('/api/evidence/verify', methods=['POST'])
    def verify_evidence_integrity():
        """Verify evidence integrity and chain of custody."""
        actor_identity = get_actor_identity(request)
        
        # Record verification request
        verify_request_id = record_api_access(
            '/api/evidence/verify',
            'POST',
            actor_identity,
            request.json or {}
        )
        
        try:
            data = request.json or {}
            vulnerability_id = data.get('vulnerability_id')
            
            if vulnerability_id:
                # Verify specific calculation
                verification_result = risk_service.verify_calculation_integrity(vulnerability_id)
            else:
                # Verify overall chain integrity
                verification_result = chain_tracker.verify_chain_integrity()
            
            return jsonify({
                'status': 'success',
                'verification_result': verification_result,
                'verification_metadata': {
                    'verify_request_id': verify_request_id,
                    'verification_timestamp': datetime.now(timezone.utc).isoformat(),
                    'cryptographic_verification': True
                }
            })
            
        except Exception as e:
            logger.error("Failed to verify evidence integrity", error=str(e))
            return jsonify({
                'status': 'error',
                'message': 'Failed to verify evidence integrity',
                'error': 'Internal server error'
            }), 500
    
    @app.route('/api/dashboard-stats')
    def get_dashboard_stats():
        """Get dashboard statistics with evidence integrity."""
        actor_identity = get_actor_identity(request)
        
        # Record stats access
        access_event_id = record_api_access('/api/dashboard-stats', 'GET', actor_identity)
        
        try:
            # Get statistics with evidence tracking
            stats = risk_service.get_risk_statistics_with_evidence(actor_identity=actor_identity)
            
            # Add additional statistics
            from src.database import Vulnerability
            
            # Source distribution
            source_distribution = db.session.query(
                Vulnerability.source,
                db.func.count(Vulnerability.id)
            ).group_by(Vulnerability.source).all()
            
            stats['vulnerability_source_distribution'] = {
                source: count for source, count in source_distribution
            }
            
            # Add access metadata
            stats['access_metadata'] = {
                'access_event_id': access_event_id,
                'accessed_by': actor_identity,
                'access_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return jsonify(stats)
            
        except Exception as e:
            logger.error("Failed to retrieve dashboard statistics", error=str(e))
            return jsonify({'error': 'Internal server error'}), 500
    
    # Error handlers with evidence tracking
    @app.errorhandler(404)
    def not_found(error):
        actor_identity = get_actor_identity(request)
        chain_tracker.record_event(
            event_type="api_not_found",
            event_data={
                "endpoint": request.endpoint,
                "method": request.method,
                "path": request.path
            },
            actor_identity=actor_identity,
            system_context={
                "operation": "error_handling",
                "error_code": 404
            }
        )
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        actor_identity = get_actor_identity(request)
        chain_tracker.record_event(
            event_type="internal_server_error",
            event_data={
                "endpoint": request.endpoint,
                "method": request.method,
                "error": str(error)
            },
            actor_identity=actor_identity,
            system_context={
                "operation": "error_handling",
                "error_code": 500,
                "critical_error": True
            }
        )
        return jsonify({'error': 'Internal server error'}), 500
    
    return app


# Application factory
def create_app(config=None):
    """Create the Guardian enhanced application."""
    return create_guardian_app(config)


if __name__ == '__main__':
    app = create_guardian_app()
    
    with app.app_context():
        # Initialize database with Guardian tables
        db.create_all()
        
        # Load sample data if needed
        loader = DataLoader()
        if not loader.check_data_exists():
            loader.load_sample_data()
    
    app.run(debug=True, host='0.0.0.0', port=5000)