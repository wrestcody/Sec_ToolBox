#!/usr/bin/env python3
"""
License Manager: Dual Licensing Implementation
Open Source + Enterprise Licensing with Feature Gating
"""

import json
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class LicenseType(Enum):
    """License types."""
    OPEN_SOURCE = "open_source"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


@dataclass
class LicenseInfo:
    """License information."""
    license_type: LicenseType
    license_key: str
    issued_to: str
    issued_date: str
    expiry_date: Optional[str]
    features: List[str]
    limits: Dict[str, int]


@dataclass
class UsageMetrics:
    """Usage tracking metrics."""
    evidence_bundles_this_month: int
    api_calls_this_month: int
    users_this_month: int
    last_reset_date: str


class LicenseManager:
    """
    Manages licensing and feature access for Compliance Ledger.
    Implements dual licensing strategy: Open Source + Enterprise.
    """
    
    def __init__(self):
        self.license_info = None
        self.usage_metrics = UsageMetrics(0, 0, 0, datetime.now(timezone.utc).isoformat())
        self.feature_flags = self._load_feature_flags()
        
    def _load_feature_flags(self) -> Dict[str, Dict[str, bool]]:
        """Load feature flags for different license types."""
        return {
            "open_source": {
                "advanced_ai": False,
                "framework_mapping": False,
                "real_time_monitoring": False,
                "cloud_storage": False,
                "custom_integrations": False,
                "multi_cloud": False,
                "api_access": False,
                "advanced_reporting": False
            },
            "professional": {
                "advanced_ai": True,
                "framework_mapping": True,
                "real_time_monitoring": False,
                "cloud_storage": True,
                "custom_integrations": False,
                "multi_cloud": False,
                "api_access": False,
                "advanced_reporting": True
            },
            "enterprise": {
                "advanced_ai": True,
                "framework_mapping": True,
                "real_time_monitoring": True,
                "cloud_storage": True,
                "custom_integrations": True,
                "multi_cloud": True,
                "api_access": True,
                "advanced_reporting": True
            }
        }
    
    def set_license(self, license_key: str, license_type: LicenseType = LicenseType.OPEN_SOURCE):
        """Set the license for the application."""
        if license_type == LicenseType.OPEN_SOURCE:
            # Open source license is always valid
            self.license_info = LicenseInfo(
                license_type=LicenseType.OPEN_SOURCE,
                license_key="MIT_LICENSE",
                issued_to="Open Source User",
                issued_date=datetime.now(timezone.utc).isoformat(),
                expiry_date=None,
                features=["basic_evidence_collection", "local_storage", "basic_ai"],
                limits={"evidence_bundles_per_month": 100, "api_calls_per_month": 1000}
            )
        else:
            # Validate commercial license
            if self._validate_license_key(license_key, license_type):
                self.license_info = self._create_license_info(license_key, license_type)
            else:
                raise ValueError(f"Invalid license key for {license_type.value}")
    
    def _validate_license_key(self, license_key: str, license_type: LicenseType) -> bool:
        """Validate a commercial license key."""
        # In a real implementation, this would validate against a license server
        # For demo purposes, we'll use a simple validation
        
        if license_type == LicenseType.PROFESSIONAL:
            # Professional license key format: PRO-XXXX-XXXX-XXXX
            return license_key.startswith("PRO-") and len(license_key) == 18
        elif license_type == LicenseType.ENTERPRISE:
            # Enterprise license key format: ENT-XXXX-XXXX-XXXX
            return license_key.startswith("ENT-") and len(license_key) == 18
        
        return False
    
    def _create_license_info(self, license_key: str, license_type: LicenseType) -> LicenseInfo:
        """Create license info for commercial licenses."""
        if license_type == LicenseType.PROFESSIONAL:
            return LicenseInfo(
                license_type=LicenseType.PROFESSIONAL,
                license_key=license_key,
                issued_to="Professional User",
                issued_date=datetime.now(timezone.utc).isoformat(),
                expiry_date=None,  # Monthly subscription
                features=["advanced_ai", "framework_mapping", "cloud_storage", "advanced_reporting"],
                limits={"evidence_bundles_per_month": 10000, "api_calls_per_month": 100000}
            )
        elif license_type == LicenseType.ENTERPRISE:
            return LicenseInfo(
                license_type=LicenseType.ENTERPRISE,
                license_key=license_key,
                issued_to="Enterprise User",
                issued_date=datetime.now(timezone.utc).isoformat(),
                expiry_date=None,  # Annual subscription
                features=["advanced_ai", "framework_mapping", "real_time_monitoring", 
                         "cloud_storage", "custom_integrations", "multi_cloud", 
                         "api_access", "advanced_reporting"],
                limits={"evidence_bundles_per_month": -1, "api_calls_per_month": -1}  # Unlimited
            )
        
        raise ValueError(f"Unsupported license type: {license_type}")
    
    def check_feature_access(self, feature_name: str) -> bool:
        """Check if the current license allows access to a specific feature."""
        if not self.license_info:
            # Default to open source if no license set
            return self.feature_flags["open_source"].get(feature_name, False)
        
        license_type = self.license_info.license_type.value
        return self.feature_flags[license_type].get(feature_name, False)
    
    def check_usage_limits(self, operation: str, count: int = 1) -> bool:
        """Check if usage is within license limits."""
        if not self.license_info:
            # Default to open source limits
            return self._check_open_source_limits(operation, count)
        
        if self.license_info.license_type == LicenseType.ENTERPRISE:
            return True  # Enterprise has unlimited usage
        
        limit_key = f"{operation}_per_month"
        current_limit = self.license_info.limits.get(limit_key, 0)
        
        if current_limit == -1:  # Unlimited
            return True
        
        current_usage = getattr(self.usage_metrics, f"{operation}_this_month", 0)
        return (current_usage + count) <= current_limit
    
    def _check_open_source_limits(self, operation: str, count: int) -> bool:
        """Check open source usage limits."""
        open_source_limits = {
            "evidence_bundles": 100,
            "api_calls": 1000
        }
        
        current_usage = getattr(self.usage_metrics, f"{operation}_this_month", 0)
        limit = open_source_limits.get(operation, 0)
        
        return (current_usage + count) <= limit
    
    def track_usage(self, operation: str, count: int = 1):
        """Track usage for licensing purposes."""
        if hasattr(self.usage_metrics, f"{operation}_this_month"):
            current_usage = getattr(self.usage_metrics, f"{operation}_this_month", 0)
            setattr(self.usage_metrics, f"{operation}_this_month", current_usage + count)
    
    def get_license_summary(self) -> Dict[str, Any]:
        """Get a summary of the current license and usage."""
        if not self.license_info:
            return {
                "license_type": "open_source",
                "status": "active",
                "features": list(self.feature_flags["open_source"].keys()),
                "usage": {
                    "evidence_bundles_this_month": self.usage_metrics.evidence_bundles_this_month,
                    "api_calls_this_month": self.usage_metrics.api_calls_this_month
                },
                "limits": {
                    "evidence_bundles_per_month": 100,
                    "api_calls_per_month": 1000
                }
            }
        
        return {
            "license_type": self.license_info.license_type.value,
            "status": "active",
            "issued_to": self.license_info.issued_to,
            "issued_date": self.license_info.issued_date,
            "features": self.license_info.features,
            "usage": {
                "evidence_bundles_this_month": self.usage_metrics.evidence_bundles_this_month,
                "api_calls_this_month": self.usage_metrics.api_calls_this_month
            },
            "limits": self.license_info.limits
        }
    
    def get_upgrade_recommendation(self) -> Optional[Dict[str, Any]]:
        """Get upgrade recommendations based on current usage."""
        if not self.license_info or self.license_info.license_type == LicenseType.ENTERPRISE:
            return None
        
        current_usage = self.usage_metrics.evidence_bundles_this_month
        current_limit = self.license_info.limits.get("evidence_bundles_per_month", 100)
        
        if current_usage > (current_limit * 0.8):  # 80% of limit
            if self.license_info.license_type == LicenseType.OPEN_SOURCE:
                return {
                    "recommended_tier": "professional",
                    "reason": f"Usage ({current_usage}) approaching open source limit ({current_limit})",
                    "benefits": [
                        "Up to 10,000 evidence bundles/month",
                        "Advanced AI analysis and recommendations",
                        "Multi-framework compliance mapping",
                        "Cloud storage integration",
                        "Email support"
                    ],
                    "cost": "$99/month"
                }
            elif self.license_info.license_type == LicenseType.PROFESSIONAL:
                return {
                    "recommended_tier": "enterprise",
                    "reason": f"Usage ({current_usage}) approaching professional limit ({current_limit})",
                    "benefits": [
                        "Unlimited evidence bundles",
                        "Real-time monitoring and alerting",
                        "Custom integrations",
                        "Dedicated support",
                        "On-premise deployment options"
                    ],
                    "cost": "Custom pricing"
                }
        
        return None


class FeatureGate:
    """Decorator for feature gating."""
    
    def __init__(self, feature_name: str):
        self.feature_name = feature_name
    
    def __call__(self, func):
        def wrapper(license_manager: LicenseManager, *args, **kwargs):
            if not license_manager.check_feature_access(self.feature_name):
                raise LicenseError(f"Feature '{self.feature_name}' requires a higher license tier")
            return func(license_manager, *args, **kwargs)
        return wrapper


class LicenseError(Exception):
    """Exception raised for license-related errors."""
    pass


def main():
    """Demo the license manager functionality."""
    print("🔐 License Manager Demo")
    print("=" * 50)
    
    # Initialize license manager
    lm = LicenseManager()
    
    # Demo 1: Open Source License
    print("\n📋 Demo 1: Open Source License")
    print("-" * 30)
    
    lm.set_license("MIT_LICENSE", LicenseType.OPEN_SOURCE)
    summary = lm.get_license_summary()
    
    print(f"License Type: {summary['license_type']}")
    print(f"Status: {summary['status']}")
    print(f"Features: {', '.join(summary['features'])}")
    print(f"Usage: {summary['usage']}")
    print(f"Limits: {summary['limits']}")
    
    # Test feature access
    print(f"\nFeature Access:")
    print(f"  Advanced AI: {lm.check_feature_access('advanced_ai')}")
    print(f"  Framework Mapping: {lm.check_feature_access('framework_mapping')}")
    print(f"  Cloud Storage: {lm.check_feature_access('cloud_storage')}")
    
    # Test usage limits
    print(f"\nUsage Limits:")
    print(f"  Can collect 50 evidence bundles: {lm.check_usage_limits('evidence_bundles', 50)}")
    print(f"  Can collect 200 evidence bundles: {lm.check_usage_limits('evidence_bundles', 200)}")
    
    # Demo 2: Professional License
    print("\n📋 Demo 2: Professional License")
    print("-" * 30)
    
    lm.set_license("PRO-1234-5678-9012", LicenseType.PROFESSIONAL)
    summary = lm.get_license_summary()
    
    print(f"License Type: {summary['license_type']}")
    print(f"Issued To: {summary['issued_to']}")
    print(f"Features: {', '.join(summary['features'])}")
    
    # Test feature access
    print(f"\nFeature Access:")
    print(f"  Advanced AI: {lm.check_feature_access('advanced_ai')}")
    print(f"  Framework Mapping: {lm.check_feature_access('framework_mapping')}")
    print(f"  Real-time Monitoring: {lm.check_feature_access('real_time_monitoring')}")
    
    # Demo 3: Enterprise License
    print("\n📋 Demo 3: Enterprise License")
    print("-" * 30)
    
    lm.set_license("ENT-ABCD-EFGH-IJKL", LicenseType.ENTERPRISE)
    summary = lm.get_license_summary()
    
    print(f"License Type: {summary['license_type']}")
    print(f"Issued To: {summary['issued_to']}")
    print(f"Features: {', '.join(summary['features'])}")
    
    # Test feature access
    print(f"\nFeature Access:")
    print(f"  Advanced AI: {lm.check_feature_access('advanced_ai')}")
    print(f"  Real-time Monitoring: {lm.check_feature_access('real_time_monitoring')}")
    print(f"  Custom Integrations: {lm.check_feature_access('custom_integrations')}")
    print(f"  API Access: {lm.check_feature_access('api_access')}")
    
    # Demo 4: Usage Tracking
    print("\n📋 Demo 4: Usage Tracking")
    print("-" * 30)
    
    # Reset to open source and track usage
    lm.set_license("MIT_LICENSE", LicenseType.OPEN_SOURCE)
    
    print("Tracking usage...")
    lm.track_usage("evidence_bundles", 50)
    lm.track_usage("evidence_bundles", 30)
    lm.track_usage("api_calls", 100)
    
    summary = lm.get_license_summary()
    print(f"Current Usage: {summary['usage']}")
    
    # Check upgrade recommendation
    recommendation = lm.get_upgrade_recommendation()
    if recommendation:
        print(f"\nUpgrade Recommendation:")
        print(f"  Recommended Tier: {recommendation['recommended_tier']}")
        print(f"  Reason: {recommendation['reason']}")
        print(f"  Cost: {recommendation['cost']}")
        print(f"  Benefits:")
        for benefit in recommendation['benefits']:
            print(f"    - {benefit}")
    
    print("\n" + "=" * 50)
    print("🎉 License Manager Demo Complete!")
    print("\nThis demonstrates:")
    print("• Feature gating based on license type")
    print("• Usage tracking and limits")
    print("• Upgrade recommendations")
    print("• Dual licensing strategy")


if __name__ == '__main__':
    main()