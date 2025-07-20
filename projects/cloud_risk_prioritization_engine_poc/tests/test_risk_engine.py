"""
Unit tests for the risk calculation engine.

These tests verify the core risk prioritization logic and ensure
that business context is properly factored into risk scoring.
"""

import pytest
from unittest.mock import Mock
import sys
import os

# Add the src directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from risk_engine import RiskCalculationEngine, RiskWeights, RiskPrioritizationService
from database import Vulnerability, Asset


class TestRiskCalculationEngine:
    """Test cases for the RiskCalculationEngine class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = RiskCalculationEngine()
        
        # Create mock vulnerability
        self.mock_vulnerability = Mock(spec=Vulnerability)
        self.mock_vulnerability.id = "test-vuln-001"
        self.mock_vulnerability.cvss_base_severity = 7.5
        self.mock_vulnerability.publicly_accessible = True
        self.mock_vulnerability.source = "AWS Security Hub"
        
        # Create mock asset
        self.mock_asset = Mock(spec=Asset)
        self.mock_asset.asset_id = "test-asset-001"
        self.mock_asset.business_impact_tier = "Tier 0: Mission Critical"
        self.mock_asset.data_sensitivity = "PII"
        self.mock_asset.cloud_tags = {
            "environment": "production",
            "pci_scope": "true",
            "owner_team": "security"
        }
    
    def test_basic_risk_calculation(self):
        """Test basic risk score calculation with all factors."""
        score, factors = self.engine.calculate_prioritized_risk_score(
            self.mock_vulnerability, self.mock_asset
        )
        
        # Should be base score (7.5) + tier bonus (30) + exposure (25) + 
        # data sensitivity (15) + CSPM bonus (5) + PCI scope (10) + production (5)
        expected_score = 7.5 + 30 + 25 + 15 + 5 + 10 + 5  # = 97.5
        
        assert score == expected_score
        assert factors["base_cvss_score"] == 7.5
        assert factors["business_impact_adjustments"]["tier_bonus"] == 30
        assert factors["exposure_adjustments"]["public_exposure"] == 25
        assert factors["business_impact_adjustments"]["data_sensitivity"] == 15
        assert factors["tool_adjustments"]["cspm_detection"] == 5
        assert factors["compliance_adjustments"]["pci_scope"] == 10
        assert factors["environment_adjustments"]["environment_bonus"] == 5
    
    def test_score_capping(self):
        """Test that risk scores are capped at maximum value."""
        # Create a high-severity vulnerability that would exceed the cap
        high_vuln = Mock(spec=Vulnerability)
        high_vuln.cvss_base_severity = 10.0
        high_vuln.publicly_accessible = True
        high_vuln.source = "AWS Security Hub"
        
        score, factors = self.engine.calculate_prioritized_risk_score(
            high_vuln, self.mock_asset
        )
        
        assert score == 100.0  # Should be capped at max
        assert factors["score_capped"] == True
    
    def test_tier_adjustments(self):
        """Test business impact tier adjustments."""
        test_cases = [
            ("Tier 0: Mission Critical", 30.0),
            ("Tier 1: High", 20.0),
            ("Tier 2: Medium", 10.0),
            ("Tier 3: Low", 0.0),
            ("Unknown Tier", 0.0)
        ]
        
        for tier, expected_adjustment in test_cases:
            adjustment = self.engine._calculate_business_tier_adjustment(tier)
            assert adjustment == expected_adjustment
    
    def test_data_sensitivity_adjustments(self):
        """Test data sensitivity adjustments."""
        test_cases = [
            ("PII", 15.0),
            ("Financial", 15.0),
            ("PHI", 20.0),
            ("Confidential", 18.0),
            ("Internal", 5.0),
            ("Public", 0.0),
            ("Unknown", 0.0)
        ]
        
        for sensitivity, expected_adjustment in test_cases:
            adjustment = self.engine._calculate_data_sensitivity_adjustment(sensitivity)
            assert adjustment == expected_adjustment
    
    def test_cloud_security_tool_detection(self):
        """Test cloud security tool detection."""
        cloud_tools = [
            "AWS Security Hub",
            "Azure Defender",
            "GCP Security Command Center",
            "AWS Config"
        ]
        
        non_cloud_tools = [
            "Qualys VMDR",
            "Tenable Nessus",
            "Rapid7 InsightVM",
            "Nmap Custom Scan"
        ]
        
        for tool in cloud_tools:
            assert self.engine._is_cloud_security_tool(tool) == True
        
        for tool in non_cloud_tools:
            assert self.engine._is_cloud_security_tool(tool) == False
    
    def test_compliance_adjustments(self):
        """Test compliance scope adjustments."""
        test_tags = {
            "pci_scope": "true",
            "sox_scope": "true",
            "hipaa_scope": "true"
        }
        
        adjustments = self.engine._calculate_compliance_adjustments(test_tags)
        
        assert adjustments["pci_scope"] == 10.0
        assert adjustments["sox_scope"] == 8.0
        assert adjustments["hipaa_scope"] == 12.0
    
    def test_environment_adjustments(self):
        """Test environment-based adjustments."""
        test_cases = [
            ({"environment": "production"}, 5.0),
            ({"environment": "staging"}, 2.0),
            ({"environment": "development"}, 0.0),
            ({}, 0.0)
        ]
        
        for tags, expected_adjustment in test_cases:
            adjustment = self.engine._calculate_environment_adjustment(tags)
            assert adjustment == expected_adjustment
    
    def test_internal_vulnerability_no_exposure_bonus(self):
        """Test that internal vulnerabilities don't get exposure bonus."""
        internal_vuln = Mock(spec=Vulnerability)
        internal_vuln.cvss_base_severity = 7.5
        internal_vuln.publicly_accessible = False
        internal_vuln.source = "Internal Scanner"
        
        score, factors = self.engine.calculate_prioritized_risk_score(
            internal_vuln, self.mock_asset
        )
        
        # Should not include the 25-point exposure bonus
        assert "public_exposure" not in factors.get("exposure_adjustments", {})
    
    def test_custom_weights(self):
        """Test engine with custom risk weights."""
        custom_weights = RiskWeights()
        custom_weights.tier_0_mission_critical = 50.0  # Increase critical tier weight
        custom_weights.publicly_accessible = 30.0     # Increase exposure weight
        
        custom_engine = RiskCalculationEngine(weights=custom_weights)
        
        score, factors = custom_engine.calculate_prioritized_risk_score(
            self.mock_vulnerability, self.mock_asset
        )
        
        # Should use custom weights
        assert factors["business_impact_adjustments"]["tier_bonus"] == 50.0
        assert factors["exposure_adjustments"]["public_exposure"] == 30.0


class TestRiskWeights:
    """Test cases for the RiskWeights configuration class."""
    
    def test_default_weights(self):
        """Test default weight values."""
        weights = RiskWeights()
        
        assert weights.tier_0_mission_critical == 30.0
        assert weights.tier_1_high == 20.0
        assert weights.tier_2_medium == 10.0
        assert weights.tier_3_low == 0.0
        assert weights.publicly_accessible == 25.0
        assert weights.pii_weight == 15.0
        assert weights.financial_weight == 15.0
        assert weights.max_score == 100.0
    
    def test_custom_weights(self):
        """Test custom weight configuration."""
        weights = RiskWeights()
        weights.tier_0_mission_critical = 40.0
        weights.publicly_accessible = 30.0
        weights.max_score = 120.0
        
        assert weights.tier_0_mission_critical == 40.0
        assert weights.publicly_accessible == 30.0
        assert weights.max_score == 120.0


@pytest.fixture
def mock_app_context():
    """Mock Flask application context for database operations."""
    from unittest.mock import patch, MagicMock
    
    with patch('src.database.db') as mock_db:
        mock_db.session = MagicMock()
        mock_db.session.query.return_value.all.return_value = []
        mock_db.session.commit.return_value = None
        yield mock_db


class TestRiskPrioritizationService:
    """Test cases for the RiskPrioritizationService class."""
    
    def test_service_initialization(self):
        """Test service initialization with default engine."""
        service = RiskPrioritizationService()
        assert service.risk_engine is not None
        assert isinstance(service.risk_engine, RiskCalculationEngine)
    
    def test_service_with_custom_engine(self):
        """Test service initialization with custom engine."""
        custom_engine = RiskCalculationEngine(weights=RiskWeights())
        service = RiskPrioritizationService(risk_engine=custom_engine)
        assert service.risk_engine == custom_engine


if __name__ == "__main__":
    pytest.main([__file__])