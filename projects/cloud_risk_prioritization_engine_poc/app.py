"""
Main Flask application for Cloud Risk Prioritization Engine.

This module creates the Flask web application with API endpoints
and web interface for demonstrating contextualized risk prioritization.
"""

import os
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import structlog

from src.database import db, get_database_url, init_db
from src.risk_engine import RiskPrioritizationService
from src.data_loader import DataLoader

# Configure structured logging
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


def create_app(config=None):
    """
    Create and configure the Flask application.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Configure CORS for API access
    CORS(app)
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Apply any additional configuration
    if config:
        app.config.update(config)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize risk prioritization service
    risk_service = RiskPrioritizationService()
    
    @app.route('/')
    def index():
        """Main dashboard page."""
        return render_template('index.html')
    
    @app.route('/health')
    def health_check():
        """Health check endpoint for monitoring."""
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'version': '1.0.0'
            })
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'error': str(e)
            }), 500
    
    @app.route('/api/vulnerabilities')
    def get_vulnerabilities():
        """
        Get all vulnerabilities with optional filtering.
        
        Query parameters:
        - limit: Maximum number of results to return
        - source: Filter by vulnerability source
        - publicly_accessible: Filter by exposure status (true/false)
        """
        try:
            from src.database import Vulnerability
            
            # Build query with optional filters
            query = Vulnerability.query
            
            # Apply filters
            source = request.args.get('source')
            if source:
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
            
            return jsonify({
                'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
                'total_count': len(vulnerabilities)
            })
            
        except Exception as e:
            logger.error("Failed to retrieve vulnerabilities", error=str(e))
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/assets')
    def get_assets():
        """
        Get all assets with optional filtering.
        
        Query parameters:
        - limit: Maximum number of results to return
        - business_tier: Filter by business impact tier
        - data_sensitivity: Filter by data sensitivity level
        """
        try:
            from src.database import Asset
            
            # Build query with optional filters
            query = Asset.query
            
            # Apply filters
            business_tier = request.args.get('business_tier')
            if business_tier:
                query = query.filter(Asset.business_impact_tier == business_tier)
            
            data_sensitivity = request.args.get('data_sensitivity')
            if data_sensitivity:
                query = query.filter(Asset.data_sensitivity == data_sensitivity)
            
            # Apply ordering and limit
            query = query.order_by(Asset.business_impact_tier, Asset.asset_id)
            
            limit = request.args.get('limit', type=int)
            if limit:
                query = query.limit(limit)
            
            assets = query.all()
            
            return jsonify({
                'assets': [asset.to_dict() for asset in assets],
                'total_count': len(assets)
            })
            
        except Exception as e:
            logger.error("Failed to retrieve assets", error=str(e))
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/prioritized-risks')
    def get_prioritized_risks():
        """
        Get vulnerabilities prioritized by contextualized risk scores.
        
        Query parameters:
        - limit: Maximum number of results to return
        - min_score: Minimum risk score to include
        - business_tier: Filter by business impact tier
        """
        try:
            limit = request.args.get('limit', type=int)
            min_score = request.args.get('min_score', type=float)
            business_tier = request.args.get('business_tier')
            
            # Get prioritized vulnerabilities
            prioritized_vulns = risk_service.get_prioritized_vulnerabilities(limit=limit)
            
            # Apply additional filters
            if min_score is not None:
                prioritized_vulns = [
                    vuln for vuln in prioritized_vulns
                    if vuln.get('prioritized_risk_score', 0) >= min_score
                ]
            
            if business_tier:
                prioritized_vulns = [
                    vuln for vuln in prioritized_vulns
                    if vuln.get('asset_context', {}).get('business_impact_tier') == business_tier
                ]
            
            return jsonify({
                'prioritized_vulnerabilities': prioritized_vulns,
                'total_count': len(prioritized_vulns)
            })
            
        except Exception as e:
            logger.error("Failed to retrieve prioritized risks", error=str(e))
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/vulnerability/<string:vuln_id>')
    def get_vulnerability_details(vuln_id):
        """Get detailed information about a specific vulnerability."""
        try:
            from src.database import Vulnerability, Asset, RiskScore
            
            # Get vulnerability with asset context and risk score
            vulnerability = Vulnerability.query.filter_by(id=vuln_id).first()
            if not vulnerability:
                return jsonify({'error': 'Vulnerability not found'}), 404
            
            asset = Asset.query.filter_by(asset_id=vulnerability.asset_id).first()
            risk_score = RiskScore.query.filter_by(vulnerability_id=vuln_id).first()
            
            # Build response
            response = vulnerability.to_dict()
            
            if asset:
                response['asset_context'] = asset.to_dict()
            
            if risk_score:
                response['prioritized_risk_score'] = risk_score.calculated_score
                response['risk_calculation_factors'] = risk_score.calculation_factors
                response['risk_calculated_at'] = risk_score.calculated_at.isoformat()
            
            return jsonify(response)
            
        except Exception as e:
            logger.error("Failed to retrieve vulnerability details", vuln_id=vuln_id, error=str(e))
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/refresh-scores', methods=['POST'])
    def refresh_risk_scores():
        """Recalculate all risk scores."""
        try:
            logger.info("Starting risk score recalculation")
            results = risk_service.calculate_all_risk_scores()
            
            return jsonify({
                'status': 'success',
                'message': 'Risk scores recalculated successfully',
                'results': results
            })
            
        except Exception as e:
            logger.error("Failed to refresh risk scores", error=str(e))
            return jsonify({
                'status': 'error',
                'message': 'Failed to refresh risk scores',
                'error': str(e)
            }), 500
    
    @app.route('/api/dashboard-stats')
    def get_dashboard_stats():
        """Get summary statistics for the dashboard."""
        try:
            stats = risk_service.get_risk_statistics()
            
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
            
            # Public exposure statistics
            public_exposure_stats = db.session.query(
                Vulnerability.publicly_accessible,
                db.func.count(Vulnerability.id)
            ).group_by(Vulnerability.publicly_accessible).all()
            
            stats['public_exposure_distribution'] = {
                'publicly_accessible': 0,
                'internal_only': 0
            }
            
            for is_public, count in public_exposure_stats:
                if is_public:
                    stats['public_exposure_distribution']['publicly_accessible'] = count
                else:
                    stats['public_exposure_distribution']['internal_only'] = count
            
            return jsonify(stats)
            
        except Exception as e:
            logger.error("Failed to retrieve dashboard statistics", error=str(e))
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/load-data', methods=['POST'])
    def load_mock_data():
        """Load mock data into the database."""
        try:
            loader = DataLoader()
            results = loader.load_all_data()
            
            # Validate data integrity
            validation = loader.validate_data_integrity()
            
            return jsonify({
                'status': 'success',
                'message': 'Mock data loaded successfully',
                'results': results,
                'validation': validation
            })
            
        except Exception as e:
            logger.error("Failed to load mock data", error=str(e))
            return jsonify({
                'status': 'error',
                'message': 'Failed to load mock data',
                'error': str(e)
            }), 500
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        if request.path.startswith('/api/'):
            return jsonify({'error': 'API endpoint not found'}), 404
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        logger.error("Internal server error", error=str(error))
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('500.html'), 500
    
    return app


def main():
    """Main function for running the application."""
    # Create the Flask app
    app = create_app()
    
    with app.app_context():
        # Initialize database tables
        logger.info("Initializing database tables")
        init_db(app)
        
        # Check if we need to load mock data
        from src.database import Vulnerability, Asset
        
        vuln_count = Vulnerability.query.count()
        asset_count = Asset.query.count()
        
        if vuln_count == 0 or asset_count == 0:
            logger.info("No data found, loading mock data")
            try:
                loader = DataLoader()
                results = loader.load_all_data()
                logger.info("Mock data loaded successfully", **results)
                
                # Calculate initial risk scores
                logger.info("Calculating initial risk scores")
                risk_service = RiskPrioritizationService()
                risk_results = risk_service.calculate_all_risk_scores()
                logger.info("Initial risk scores calculated", **risk_results)
                
            except Exception as e:
                logger.error("Failed to load initial data", error=str(e))
        else:
            logger.info(
                "Existing data found",
                vulnerabilities=vuln_count,
                assets=asset_count
            )
    
    # Get configuration from environment
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(
        "Starting Cloud Risk Prioritization Engine",
        host=host,
        port=port,
        debug=debug
    )
    
    # Run the application
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    main()