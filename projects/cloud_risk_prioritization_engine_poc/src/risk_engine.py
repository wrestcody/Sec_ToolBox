"""
Risk Prioritization Engine for Cloud Security Vulnerabilities.

This module implements the core business logic for calculating contextualized
risk scores based on technical vulnerability data and business asset context.
"""

from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
import structlog

from .database import Vulnerability, Asset, RiskScore, db

# Configure structured logging
logger = structlog.get_logger(__name__)


@dataclass
class RiskWeights:
    """
    Configuration class for risk calculation weights.
    
    This allows for easy adjustment of the risk calculation algorithm
    based on organizational priorities and risk tolerance.
    """
    
    # Business Impact Tier weights
    tier_0_mission_critical: float = 30.0
    tier_1_high: float = 20.0
    tier_2_medium: float = 10.0
    tier_3_low: float = 0.0
    
    # Exposure weights
    publicly_accessible: float = 25.0
    
    # Data sensitivity weights
    pii_weight: float = 15.0
    financial_weight: float = 15.0
    phi_weight: float = 20.0  # Protected Health Information
    confidential_weight: float = 18.0
    
    # Compliance scope weights
    pci_scope: float = 10.0
    sox_scope: float = 8.0
    hipaa_scope: float = 12.0
    
    # Environment weights
    production_environment: float = 5.0
    staging_environment: float = 2.0
    
    # Security tool weights (CSPM detection bonus)
    cloud_security_tool_bonus: float = 5.0
    
    # Maximum score cap
    max_score: float = 100.0


class RiskCalculationEngine:
    """
    Core engine for calculating contextualized risk scores.
    
    This class implements the business logic for combining technical
    vulnerability severity with business context to produce actionable
    risk prioritization scores.
    """
    
    def __init__(self, weights: Optional[RiskWeights] = None):
        """
        Initialize the risk calculation engine.
        
        Args:
            weights: Custom risk weights configuration
        """
        self.weights = weights or RiskWeights()
        self.logger = logger.bind(component="risk_engine")
    
    def calculate_prioritized_risk_score(
        self, 
        vulnerability: Vulnerability, 
        asset_context: Asset
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Calculate the contextualized risk score for a vulnerability.
        
        Args:
            vulnerability: The vulnerability object with technical details
            asset_context: The asset object with business context
            
        Returns:
            Tuple of (calculated_score, calculation_factors)
        """
        # Start with the base CVSS score
        base_score = vulnerability.cvss_base_severity
        
        # Track calculation factors for transparency and audit
        calculation_factors = {
            "base_cvss_score": base_score,
            "business_impact_adjustments": {},
            "exposure_adjustments": {},
            "compliance_adjustments": {},
            "environment_adjustments": {},
            "tool_adjustments": {}
        }
        
        # Business Impact Tier adjustment
        tier_adjustment = self._calculate_business_tier_adjustment(
            asset_context.business_impact_tier
        )
        base_score += tier_adjustment
        calculation_factors["business_impact_adjustments"]["tier_bonus"] = tier_adjustment
        
        # Internet exposure adjustment
        if vulnerability.publicly_accessible:
            exposure_adjustment = self.weights.publicly_accessible
            base_score += exposure_adjustment
            calculation_factors["exposure_adjustments"]["public_exposure"] = exposure_adjustment
        
        # Data sensitivity adjustment
        sensitivity_adjustment = self._calculate_data_sensitivity_adjustment(
            asset_context.data_sensitivity
        )
        base_score += sensitivity_adjustment
        calculation_factors["business_impact_adjustments"]["data_sensitivity"] = sensitivity_adjustment
        
        # Cloud security tool detection bonus
        if self._is_cloud_security_tool(vulnerability.source):
            tool_bonus = self.weights.cloud_security_tool_bonus
            base_score += tool_bonus
            calculation_factors["tool_adjustments"]["cspm_detection"] = tool_bonus
        
        # Compliance scope adjustments
        compliance_adjustments = self._calculate_compliance_adjustments(
            asset_context.cloud_tags or {}
        )
        for compliance_type, adjustment in compliance_adjustments.items():
            base_score += adjustment
            calculation_factors["compliance_adjustments"][compliance_type] = adjustment
        
        # Environment adjustments
        environment_adjustment = self._calculate_environment_adjustment(
            asset_context.cloud_tags or {}
        )
        base_score += environment_adjustment
        calculation_factors["environment_adjustments"]["environment_bonus"] = environment_adjustment
        
        # Cap the final score
        final_score = min(base_score, self.weights.max_score)
        calculation_factors["final_score"] = final_score
        calculation_factors["score_capped"] = final_score == self.weights.max_score
        
        self.logger.info(
            "Risk score calculated",
            vulnerability_id=vulnerability.id,
            asset_id=asset_context.asset_id,
            base_cvss=vulnerability.cvss_base_severity,
            final_score=final_score,
            business_tier=asset_context.business_impact_tier,
            data_sensitivity=asset_context.data_sensitivity,
            publicly_accessible=vulnerability.publicly_accessible
        )
        
        return final_score, calculation_factors
    
    def _calculate_business_tier_adjustment(self, business_tier: str) -> float:
        """Calculate risk adjustment based on business impact tier."""
        tier_mapping = {
            "Tier 0: Mission Critical": self.weights.tier_0_mission_critical,
            "Tier 1: High": self.weights.tier_1_high,
            "Tier 2: Medium": self.weights.tier_2_medium,
            "Tier 3: Low": self.weights.tier_3_low
        }
        return tier_mapping.get(business_tier, 0.0)
    
    def _calculate_data_sensitivity_adjustment(self, data_sensitivity: str) -> float:
        """Calculate risk adjustment based on data sensitivity classification."""
        sensitivity_mapping = {
            "PII": self.weights.pii_weight,
            "Financial": self.weights.financial_weight,
            "PHI": self.weights.phi_weight,
            "Confidential": self.weights.confidential_weight,
            "Internal": 5.0,
            "Public": 0.0
        }
        return sensitivity_mapping.get(data_sensitivity, 0.0)
    
    def _is_cloud_security_tool(self, source: str) -> bool:
        """Determine if the vulnerability source is a cloud security platform."""
        cloud_security_tools = {
            "AWS Security Hub",
            "Azure Defender",
            "Azure Security Center",
            "GCP Security Command Center",
            "Google Security Command Center",
            "AWS Config",
            "Azure Policy",
            "GCP Cloud Asset Inventory"
        }
        return source in cloud_security_tools
    
    def _calculate_compliance_adjustments(self, cloud_tags: Dict[str, Any]) -> Dict[str, float]:
        """Calculate risk adjustments based on compliance scope tags."""
        adjustments = {}
        
        if cloud_tags.get("pci_scope") == "true":
            adjustments["pci_scope"] = self.weights.pci_scope
        
        if cloud_tags.get("sox_scope") == "true":
            adjustments["sox_scope"] = self.weights.sox_scope
        
        if cloud_tags.get("hipaa_scope") == "true":
            adjustments["hipaa_scope"] = self.weights.hipaa_scope
        
        return adjustments
    
    def _calculate_environment_adjustment(self, cloud_tags: Dict[str, Any]) -> float:
        """Calculate risk adjustment based on environment type."""
        environment = cloud_tags.get("environment", "").lower()
        
        if environment == "production":
            return self.weights.production_environment
        elif environment == "staging":
            return self.weights.staging_environment
        
        return 0.0


class RiskPrioritizationService:
    """
    Service class for managing risk prioritization operations.
    
    This class provides high-level operations for calculating, storing,
    and retrieving risk prioritization data.
    """
    
    def __init__(self, risk_engine: Optional[RiskCalculationEngine] = None):
        """
        Initialize the risk prioritization service.
        
        Args:
            risk_engine: Custom risk calculation engine
        """
        self.risk_engine = risk_engine or RiskCalculationEngine()
        self.logger = logger.bind(component="risk_service")
    
    def calculate_all_risk_scores(self) -> Dict[str, Any]:
        """
        Calculate risk scores for all vulnerabilities in the database.
        
        Returns:
            Dictionary with calculation results and statistics
        """
        self.logger.info("Starting risk score calculation for all vulnerabilities")
        
        # Get all vulnerabilities and assets
        vulnerabilities = Vulnerability.query.all()
        assets = {asset.asset_id: asset for asset in Asset.query.all()}
        
        calculation_results = {
            "total_vulnerabilities": len(vulnerabilities),
            "successful_calculations": 0,
            "failed_calculations": 0,
            "missing_assets": 0,
            "risk_scores": []
        }
        
        for vulnerability in vulnerabilities:
            asset = assets.get(vulnerability.asset_id)
            
            if not asset:
                self.logger.warning(
                    "Asset not found for vulnerability",
                    vulnerability_id=vulnerability.id,
                    asset_id=vulnerability.asset_id
                )
                calculation_results["missing_assets"] += 1
                continue
            
            try:
                # Calculate the risk score
                score, factors = self.risk_engine.calculate_prioritized_risk_score(
                    vulnerability, asset
                )
                
                # Store or update the risk score in database
                existing_score = RiskScore.query.filter_by(
                    vulnerability_id=vulnerability.id
                ).first()
                
                if existing_score:
                    existing_score.calculated_score = score
                    existing_score.calculation_factors = factors
                    existing_score.calculated_at = db.func.now()
                else:
                    new_score = RiskScore(
                        vulnerability_id=vulnerability.id,
                        calculated_score=score,
                        calculation_factors=factors
                    )
                    db.session.add(new_score)
                
                calculation_results["successful_calculations"] += 1
                calculation_results["risk_scores"].append({
                    "vulnerability_id": vulnerability.id,
                    "calculated_score": score,
                    "factors": factors
                })
                
            except Exception as e:
                self.logger.error(
                    "Failed to calculate risk score",
                    vulnerability_id=vulnerability.id,
                    error=str(e)
                )
                calculation_results["failed_calculations"] += 1
        
        # Commit all changes to database
        try:
            db.session.commit()
            self.logger.info(
                "Risk score calculation completed",
                **{k: v for k, v in calculation_results.items() if k != "risk_scores"}
            )
        except Exception as e:
            db.session.rollback()
            self.logger.error("Failed to save risk scores to database", error=str(e))
            raise
        
        return calculation_results
    
    def get_prioritized_vulnerabilities(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities ordered by their prioritized risk scores.
        
        Args:
            limit: Maximum number of vulnerabilities to return
            
        Returns:
            List of vulnerability data with risk scores and asset context
        """
        # Query to get vulnerabilities with their latest risk scores and asset context
        query = db.session.query(
            Vulnerability,
            Asset,
            RiskScore
        ).join(
            Asset, Vulnerability.asset_id == Asset.asset_id
        ).outerjoin(
            RiskScore, Vulnerability.id == RiskScore.vulnerability_id
        ).order_by(
            RiskScore.calculated_score.desc().nullslast(),
            Vulnerability.cvss_base_severity.desc()
        )
        
        if limit:
            query = query.limit(limit)
        
        results = []
        for vulnerability, asset, risk_score in query.all():
            vuln_dict = vulnerability.to_dict()
            asset_dict = asset.to_dict()
            
            # Add risk score information
            if risk_score:
                vuln_dict["prioritized_risk_score"] = risk_score.calculated_score
                vuln_dict["risk_calculation_factors"] = risk_score.calculation_factors
                vuln_dict["risk_calculated_at"] = risk_score.calculated_at.isoformat()
            else:
                vuln_dict["prioritized_risk_score"] = None
                vuln_dict["risk_calculation_factors"] = {}
                vuln_dict["risk_calculated_at"] = None
            
            # Add asset context
            vuln_dict["asset_context"] = asset_dict
            
            results.append(vuln_dict)
        
        self.logger.info(
            "Retrieved prioritized vulnerabilities",
            count=len(results),
            limit=limit
        )
        
        return results
    
    def get_risk_statistics(self) -> Dict[str, Any]:
        """
        Get summary statistics about risk scores and vulnerabilities.
        
        Returns:
            Dictionary with various risk statistics
        """
        # Basic counts
        total_vulnerabilities = Vulnerability.query.count()
        total_assets = Asset.query.count()
        scored_vulnerabilities = RiskScore.query.count()
        
        # Risk score statistics
        risk_scores = db.session.query(RiskScore.calculated_score).all()
        scores = [score[0] for score in risk_scores]
        
        statistics = {
            "total_vulnerabilities": total_vulnerabilities,
            "total_assets": total_assets,
            "scored_vulnerabilities": scored_vulnerabilities,
            "unscored_vulnerabilities": total_vulnerabilities - scored_vulnerabilities,
        }
        
        if scores:
            statistics.update({
                "average_risk_score": sum(scores) / len(scores),
                "max_risk_score": max(scores),
                "min_risk_score": min(scores),
                "high_risk_count": len([s for s in scores if s >= 80]),
                "medium_risk_count": len([s for s in scores if 50 <= s < 80]),
                "low_risk_count": len([s for s in scores if s < 50])
            })
        
        # Business tier distribution
        tier_distribution = db.session.query(
            Asset.business_impact_tier,
            db.func.count(Asset.asset_id)
        ).group_by(Asset.business_impact_tier).all()
        
        statistics["business_tier_distribution"] = {
            tier: count for tier, count in tier_distribution
        }
        
        # Data sensitivity distribution
        sensitivity_distribution = db.session.query(
            Asset.data_sensitivity,
            db.func.count(Asset.asset_id)
        ).group_by(Asset.data_sensitivity).all()
        
        statistics["data_sensitivity_distribution"] = {
            sensitivity: count for sensitivity, count in sensitivity_distribution
        }
        
        return statistics