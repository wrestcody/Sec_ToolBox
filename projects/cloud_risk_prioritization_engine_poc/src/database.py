"""
Database models and configuration for Cloud Risk Prioritization Engine.

This module defines the SQLAlchemy models for vulnerabilities, assets, and risk scores,
along with database initialization and configuration functions.
"""

import os
from datetime import datetime
from typing import Dict, Any, Optional
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON, Float, String, Boolean, DateTime, Text, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Create the database instance
db = SQLAlchemy()


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


# Bind the base to our db instance
db.Model = Base


class Vulnerability(db.Model):
    """
    Model representing a security vulnerability finding.
    
    This model stores vulnerability information from various security tools
    and scanners, including both technical details and remediation guidance.
    """
    
    __tablename__ = 'vulnerabilities'
    
    # Primary key and identification
    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    
    # Source and vulnerability details
    source: Mapped[str] = mapped_column(String(100), nullable=False, 
                                       comment="Security tool that discovered this vulnerability")
    name: Mapped[str] = mapped_column(String(255), nullable=False,
                                     comment="Human-readable vulnerability name")
    cvss_base_severity: Mapped[float] = mapped_column(Float, nullable=False,
                                                      comment="CVSS base score (0.0-10.0)")
    
    # Asset relationship
    asset_id: Mapped[str] = mapped_column(String(50), nullable=False,
                                         comment="ID of the affected asset")
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False,
                                           comment="Type of cloud resource (EC2, S3, etc.)")
    
    # Risk context
    publicly_accessible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False,
                                                      comment="Whether the asset is internet-facing")
    
    # Remediation information
    remediation_steps_cloud_native: Mapped[Optional[str]] = mapped_column(Text,
                                                                          comment="Cloud-native remediation steps")
    
    # Metadata
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow,
                                                   comment="When the vulnerability was discovered")
    
    def __repr__(self) -> str:
        return f"<Vulnerability {self.id}: {self.name}>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the vulnerability to a dictionary for JSON serialization."""
        return {
            'id': self.id,
            'source': self.source,
            'name': self.name,
            'cvss_base_severity': self.cvss_base_severity,
            'asset_id': self.asset_id,
            'asset_type': self.asset_type,
            'publicly_accessible': self.publicly_accessible,
            'remediation_steps_cloud_native': self.remediation_steps_cloud_native,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }


class Asset(db.Model):
    """
    Model representing a cloud asset with business context.
    
    This model stores business-critical information about cloud resources
    that is used to calculate contextual risk scores.
    """
    
    __tablename__ = 'assets'
    
    # Primary key
    asset_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    
    # Business context
    cloud_tags: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON,
                                                                comment="Cloud resource tags as JSON")
    business_impact_tier: Mapped[str] = mapped_column(String(100), nullable=False,
                                                     comment="Business criticality tier")
    data_sensitivity: Mapped[str] = mapped_column(String(50), nullable=False,
                                                 comment="Data sensitivity classification")
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow,
                                                comment="When the asset record was created")
    
    def __repr__(self) -> str:
        return f"<Asset {self.asset_id}: {self.business_impact_tier}>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the asset to a dictionary for JSON serialization."""
        return {
            'asset_id': self.asset_id,
            'cloud_tags': self.cloud_tags or {},
            'business_impact_tier': self.business_impact_tier,
            'data_sensitivity': self.data_sensitivity,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class RiskScore(db.Model):
    """
    Model representing calculated risk scores for vulnerabilities.
    
    This model tracks the history of risk score calculations and the factors
    that contributed to each score, providing audit trails and analysis capabilities.
    """
    
    __tablename__ = 'risk_scores'
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to vulnerability
    vulnerability_id: Mapped[str] = mapped_column(String(50), nullable=False,
                                                 comment="ID of the vulnerability being scored")
    
    # Score and calculation details
    calculated_score: Mapped[float] = mapped_column(Float, nullable=False,
                                                   comment="Final calculated risk score")
    calculation_factors: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON,
                                                                          comment="Factors used in calculation")
    
    # Metadata
    calculated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow,
                                                   comment="When the score was calculated")
    
    def __repr__(self) -> str:
        return f"<RiskScore {self.vulnerability_id}: {self.calculated_score}>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the risk score to a dictionary for JSON serialization."""
        return {
            'id': self.id,
            'vulnerability_id': self.vulnerability_id,
            'calculated_score': self.calculated_score,
            'calculation_factors': self.calculation_factors or {},
            'calculated_at': self.calculated_at.isoformat() if self.calculated_at else None
        }


def get_database_url() -> str:
    """
    Get the database URL from environment variables with fallback options.
    
    Returns:
        str: Database URL for SQLAlchemy
    """
    # Check for PostgreSQL URL first (production/Replit)
    postgres_url = os.getenv('DATABASE_URL')
    if postgres_url:
        # Handle the postgresql:// vs postgresql+psycopg2:// URL format
        if postgres_url.startswith('postgres://'):
            postgres_url = postgres_url.replace('postgres://', 'postgresql+psycopg2://', 1)
        elif not postgres_url.startswith('postgresql+psycopg2://'):
            if postgres_url.startswith('postgresql://'):
                postgres_url = postgres_url.replace('postgresql://', 'postgresql+psycopg2://', 1)
        return postgres_url
    
    # Fallback to individual PostgreSQL connection parameters
    postgres_host = os.getenv('POSTGRES_HOST', 'localhost')
    postgres_port = os.getenv('POSTGRES_PORT', '5432')
    postgres_db = os.getenv('POSTGRES_DB', 'cloud_risk_db')
    postgres_user = os.getenv('POSTGRES_USER', 'postgres')
    postgres_password = os.getenv('POSTGRES_PASSWORD', 'password')
    
    if postgres_password:
        return f"postgresql+psycopg2://{postgres_user}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}"
    
    # Final fallback to SQLite for local development
    return "sqlite:///cloud_risk_prioritization.db"


def init_db(app=None) -> None:
    """
    Initialize the database with all tables.
    
    Args:
        app: Flask application instance (optional)
    """
    if app:
        with app.app_context():
            db.create_all()
            print("Database tables created successfully!")
    else:
        # For standalone usage
        from flask import Flask
        temp_app = Flask(__name__)
        temp_app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
        temp_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        db.init_app(temp_app)
        
        with temp_app.app_context():
            db.create_all()
            print("Database tables created successfully!")


def drop_all_tables(app=None) -> None:
    """
    Drop all database tables. Use with caution!
    
    Args:
        app: Flask application instance (optional)
    """
    if app:
        with app.app_context():
            db.drop_all()
            print("All database tables dropped!")
    else:
        # For standalone usage
        from flask import Flask
        temp_app = Flask(__name__)
        temp_app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
        temp_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        db.init_app(temp_app)
        
        with temp_app.app_context():
            db.drop_all()
            print("All database tables dropped!")


if __name__ == "__main__":
    # Allow running this module directly to initialize the database
    print(f"Database URL: {get_database_url()}")
    print("Initializing database...")
    init_db()