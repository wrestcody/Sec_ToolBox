"""
Data loader for importing mock vulnerability and asset data.

This module handles loading the mock JSON data into the database,
providing a clean way to populate the system for demonstration purposes.
"""

import json
import os
from typing import Dict, Any, List
from pathlib import Path
import structlog

from .database import db, Vulnerability, Asset, init_db

# Configure structured logging
logger = structlog.get_logger(__name__)


class DataLoader:
    """
    Service for loading mock data into the database.
    
    This class handles the import of vulnerability and asset data from JSON files,
    with proper error handling and validation.
    """
    
    def __init__(self, data_dir: str = None):
        """
        Initialize the data loader.
        
        Args:
            data_dir: Directory containing the mock data files
        """
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            # Default to the data directory relative to this file
            current_dir = Path(__file__).parent.parent
            self.data_dir = current_dir / "data"
        
        self.logger = logger.bind(component="data_loader")
    
    def load_vulnerabilities(self, filename: str = "mock_vulnerabilities.json") -> int:
        """
        Load vulnerability data from JSON file into the database.
        
        Args:
            filename: Name of the JSON file containing vulnerability data
            
        Returns:
            Number of vulnerabilities loaded
        """
        file_path = self.data_dir / filename
        
        if not file_path.exists():
            raise FileNotFoundError(f"Vulnerability data file not found: {file_path}")
        
        self.logger.info("Loading vulnerability data", file_path=str(file_path))
        
        with open(file_path, 'r') as f:
            vulnerability_data = json.load(f)
        
        loaded_count = 0
        for vuln_dict in vulnerability_data:
            try:
                # Check if vulnerability already exists
                existing_vuln = Vulnerability.query.filter_by(id=vuln_dict['id']).first()
                
                if existing_vuln:
                    # Update existing vulnerability
                    self._update_vulnerability(existing_vuln, vuln_dict)
                    self.logger.debug("Updated existing vulnerability", vuln_id=vuln_dict['id'])
                else:
                    # Create new vulnerability
                    vulnerability = self._create_vulnerability(vuln_dict)
                    db.session.add(vulnerability)
                    self.logger.debug("Created new vulnerability", vuln_id=vuln_dict['id'])
                
                loaded_count += 1
                
            except Exception as e:
                self.logger.error(
                    "Failed to load vulnerability",
                    vuln_id=vuln_dict.get('id', 'unknown'),
                    error=str(e)
                )
                # Continue processing other vulnerabilities
                continue
        
        try:
            db.session.commit()
            self.logger.info(
                "Vulnerability data loaded successfully",
                total_loaded=loaded_count,
                total_in_file=len(vulnerability_data)
            )
        except Exception as e:
            db.session.rollback()
            self.logger.error("Failed to commit vulnerability data", error=str(e))
            raise
        
        return loaded_count
    
    def load_assets(self, filename: str = "mock_assets.json") -> int:
        """
        Load asset data from JSON file into the database.
        
        Args:
            filename: Name of the JSON file containing asset data
            
        Returns:
            Number of assets loaded
        """
        file_path = self.data_dir / filename
        
        if not file_path.exists():
            raise FileNotFoundError(f"Asset data file not found: {file_path}")
        
        self.logger.info("Loading asset data", file_path=str(file_path))
        
        with open(file_path, 'r') as f:
            asset_data = json.load(f)
        
        loaded_count = 0
        for asset_dict in asset_data:
            try:
                # Check if asset already exists
                existing_asset = Asset.query.filter_by(asset_id=asset_dict['asset_id']).first()
                
                if existing_asset:
                    # Update existing asset
                    self._update_asset(existing_asset, asset_dict)
                    self.logger.debug("Updated existing asset", asset_id=asset_dict['asset_id'])
                else:
                    # Create new asset
                    asset = self._create_asset(asset_dict)
                    db.session.add(asset)
                    self.logger.debug("Created new asset", asset_id=asset_dict['asset_id'])
                
                loaded_count += 1
                
            except Exception as e:
                self.logger.error(
                    "Failed to load asset",
                    asset_id=asset_dict.get('asset_id', 'unknown'),
                    error=str(e)
                )
                # Continue processing other assets
                continue
        
        try:
            db.session.commit()
            self.logger.info(
                "Asset data loaded successfully",
                total_loaded=loaded_count,
                total_in_file=len(asset_data)
            )
        except Exception as e:
            db.session.rollback()
            self.logger.error("Failed to commit asset data", error=str(e))
            raise
        
        return loaded_count
    
    def load_all_data(self) -> Dict[str, int]:
        """
        Load both vulnerability and asset data.
        
        Returns:
            Dictionary with counts of loaded vulnerabilities and assets
        """
        results = {}
        
        try:
            results['vulnerabilities'] = self.load_vulnerabilities()
        except Exception as e:
            self.logger.error("Failed to load vulnerabilities", error=str(e))
            results['vulnerabilities'] = 0
        
        try:
            results['assets'] = self.load_assets()
        except Exception as e:
            self.logger.error("Failed to load assets", error=str(e))
            results['assets'] = 0
        
        self.logger.info("Data loading completed", **results)
        return results
    
    def _create_vulnerability(self, vuln_dict: Dict[str, Any]) -> Vulnerability:
        """Create a new Vulnerability object from dictionary data."""
        return Vulnerability(
            id=vuln_dict['id'],
            source=vuln_dict['source'],
            name=vuln_dict['name'],
            cvss_base_severity=float(vuln_dict['cvss_base_severity']),
            asset_id=vuln_dict['asset_id'],
            asset_type=vuln_dict['asset_type'],
            publicly_accessible=bool(vuln_dict['publicly_accessible']),
            remediation_steps_cloud_native=vuln_dict.get('remediation_steps_cloud_native')
        )
    
    def _update_vulnerability(self, vulnerability: Vulnerability, vuln_dict: Dict[str, Any]) -> None:
        """Update an existing Vulnerability object with new data."""
        vulnerability.source = vuln_dict['source']
        vulnerability.name = vuln_dict['name']
        vulnerability.cvss_base_severity = float(vuln_dict['cvss_base_severity'])
        vulnerability.asset_id = vuln_dict['asset_id']
        vulnerability.asset_type = vuln_dict['asset_type']
        vulnerability.publicly_accessible = bool(vuln_dict['publicly_accessible'])
        vulnerability.remediation_steps_cloud_native = vuln_dict.get('remediation_steps_cloud_native')
    
    def _create_asset(self, asset_dict: Dict[str, Any]) -> Asset:
        """Create a new Asset object from dictionary data."""
        return Asset(
            asset_id=asset_dict['asset_id'],
            cloud_tags=asset_dict.get('cloud_tags', {}),
            business_impact_tier=asset_dict['business_impact_tier'],
            data_sensitivity=asset_dict['data_sensitivity']
        )
    
    def _update_asset(self, asset: Asset, asset_dict: Dict[str, Any]) -> None:
        """Update an existing Asset object with new data."""
        asset.cloud_tags = asset_dict.get('cloud_tags', {})
        asset.business_impact_tier = asset_dict['business_impact_tier']
        asset.data_sensitivity = asset_dict['data_sensitivity']
    
    def clear_all_data(self) -> None:
        """
        Clear all data from the database tables.
        
        WARNING: This will delete all data!
        """
        self.logger.warning("Clearing all data from database")
        
        try:
            # Delete in order to respect foreign key constraints
            db.session.query(Vulnerability).delete()
            db.session.query(Asset).delete()
            db.session.commit()
            
            self.logger.info("All data cleared successfully")
        except Exception as e:
            db.session.rollback()
            self.logger.error("Failed to clear data", error=str(e))
            raise
    
    def validate_data_integrity(self) -> Dict[str, Any]:
        """
        Validate the integrity of loaded data.
        
        Returns:
            Dictionary with validation results
        """
        self.logger.info("Validating data integrity")
        
        validation_results = {
            "total_vulnerabilities": 0,
            "total_assets": 0,
            "orphaned_vulnerabilities": 0,
            "missing_assets": [],
            "validation_passed": True
        }
        
        # Count total records
        validation_results["total_vulnerabilities"] = Vulnerability.query.count()
        validation_results["total_assets"] = Asset.query.count()
        
        # Check for orphaned vulnerabilities (vulnerabilities without matching assets)
        vulnerabilities = Vulnerability.query.all()
        asset_ids = {asset.asset_id for asset in Asset.query.all()}
        
        for vulnerability in vulnerabilities:
            if vulnerability.asset_id not in asset_ids:
                validation_results["orphaned_vulnerabilities"] += 1
                validation_results["missing_assets"].append({
                    "vulnerability_id": vulnerability.id,
                    "missing_asset_id": vulnerability.asset_id
                })
                validation_results["validation_passed"] = False
        
        # Log validation results
        if validation_results["validation_passed"]:
            self.logger.info("Data integrity validation passed", **validation_results)
        else:
            self.logger.warning("Data integrity validation failed", **validation_results)
        
        return validation_results


def main():
    """
    Main function for running the data loader as a standalone script.
    """
    import sys
    from flask import Flask
    
    # Create a minimal Flask app for database context
    app = Flask(__name__)
    
    # Configure database
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL', 
        'sqlite:///cloud_risk_prioritization.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    from .database import db
    db.init_app(app)
    
    with app.app_context():
        # Initialize tables if they don't exist
        print("Initializing database...")
        init_db(app)
        
        # Load data
        loader = DataLoader()
        
        if len(sys.argv) > 1 and sys.argv[1] == "--clear":
            print("Clearing existing data...")
            loader.clear_all_data()
        
        print("Loading mock data...")
        results = loader.load_all_data()
        
        print(f"Loaded {results['vulnerabilities']} vulnerabilities")
        print(f"Loaded {results['assets']} assets")
        
        # Validate data integrity
        print("Validating data integrity...")
        validation = loader.validate_data_integrity()
        
        if validation["validation_passed"]:
            print("✅ Data validation passed!")
        else:
            print("❌ Data validation failed!")
            print(f"Found {validation['orphaned_vulnerabilities']} orphaned vulnerabilities")
        
        print("Data loading completed successfully!")


if __name__ == "__main__":
    main()