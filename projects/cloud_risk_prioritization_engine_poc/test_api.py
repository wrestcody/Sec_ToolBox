#!/usr/bin/env python3
"""
API Test Script for Cloud Risk Prioritization Engine

This script tests the main API endpoints to ensure the application
is working correctly after setup.
"""

import requests
import json
import sys
import time
from typing import Dict, Any


class APITester:
    """Simple API testing class for the risk prioritization engine."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_health_check(self) -> bool:
        """Test the health check endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Health Check: {data['status']}")
                return True
            else:
                print(f"❌ Health Check Failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Health Check Error: {e}")
            return False
    
    def test_vulnerabilities_endpoint(self) -> bool:
        """Test the vulnerabilities API endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/api/vulnerabilities")
            if response.status_code == 200:
                data = response.json()
                count = data.get('total_count', 0)
                print(f"✅ Vulnerabilities API: {count} vulnerabilities found")
                return count > 0
            else:
                print(f"❌ Vulnerabilities API Failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Vulnerabilities API Error: {e}")
            return False
    
    def test_assets_endpoint(self) -> bool:
        """Test the assets API endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/api/assets")
            if response.status_code == 200:
                data = response.json()
                count = data.get('total_count', 0)
                print(f"✅ Assets API: {count} assets found")
                return count > 0
            else:
                print(f"❌ Assets API Failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Assets API Error: {e}")
            return False
    
    def test_prioritized_risks_endpoint(self) -> bool:
        """Test the prioritized risks API endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/api/prioritized-risks")
            if response.status_code == 200:
                data = response.json()
                count = data.get('total_count', 0)
                vulnerabilities = data.get('prioritized_vulnerabilities', [])
                
                print(f"✅ Prioritized Risks API: {count} prioritized vulnerabilities")
                
                # Check if risk scores are calculated
                scored_count = sum(1 for v in vulnerabilities if v.get('prioritized_risk_score') is not None)
                print(f"   📊 {scored_count} vulnerabilities have calculated risk scores")
                
                # Show top 3 risks
                if vulnerabilities:
                    print("   🔝 Top 3 Risks:")
                    for i, vuln in enumerate(vulnerabilities[:3]):
                        risk_score = vuln.get('prioritized_risk_score', 0)
                        name = vuln.get('name', 'Unknown')
                        asset_id = vuln.get('asset_id', 'Unknown')
                        print(f"      {i+1}. {name} (Asset: {asset_id}) - Score: {risk_score:.1f}")
                
                return count > 0
            else:
                print(f"❌ Prioritized Risks API Failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Prioritized Risks API Error: {e}")
            return False
    
    def test_dashboard_stats_endpoint(self) -> bool:
        """Test the dashboard stats API endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/api/dashboard-stats")
            if response.status_code == 200:
                data = response.json()
                
                print("✅ Dashboard Stats API:")
                print(f"   📊 Total Vulnerabilities: {data.get('total_vulnerabilities', 0)}")
                print(f"   🏢 Total Assets: {data.get('total_assets', 0)}")
                print(f"   🚨 High Risk Count: {data.get('high_risk_count', 0)}")
                print(f"   🌐 Publicly Accessible: {data.get('public_exposure_distribution', {}).get('publicly_accessible', 0)}")
                
                return True
            else:
                print(f"❌ Dashboard Stats API Failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Dashboard Stats API Error: {e}")
            return False
    
    def test_vulnerability_details(self) -> bool:
        """Test the vulnerability details endpoint."""
        try:
            # First get a vulnerability ID
            response = self.session.get(f"{self.base_url}/api/vulnerabilities?limit=1")
            if response.status_code != 200:
                print("❌ Cannot get vulnerability for details test")
                return False
            
            vulnerabilities = response.json().get('vulnerabilities', [])
            if not vulnerabilities:
                print("❌ No vulnerabilities available for details test")
                return False
            
            vuln_id = vulnerabilities[0]['id']
            
            # Test the details endpoint
            response = self.session.get(f"{self.base_url}/api/vulnerability/{vuln_id}")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Vulnerability Details API: Retrieved details for {vuln_id}")
                
                # Check if asset context is included
                if 'asset_context' in data:
                    print("   🏢 Asset context included")
                
                # Check if risk score is calculated
                if data.get('prioritized_risk_score') is not None:
                    print(f"   📊 Risk score: {data['prioritized_risk_score']:.1f}")
                
                return True
            else:
                print(f"❌ Vulnerability Details API Failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Vulnerability Details API Error: {e}")
            return False
    
    def run_all_tests(self) -> bool:
        """Run all API tests."""
        print("🧪 Running API Tests for Cloud Risk Prioritization Engine\n")
        
        tests = [
            ("Health Check", self.test_health_check),
            ("Vulnerabilities Endpoint", self.test_vulnerabilities_endpoint),
            ("Assets Endpoint", self.test_assets_endpoint),
            ("Prioritized Risks Endpoint", self.test_prioritized_risks_endpoint),
            ("Dashboard Stats Endpoint", self.test_dashboard_stats_endpoint),
            ("Vulnerability Details Endpoint", self.test_vulnerability_details),
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔍 Testing {test_name}...")
            try:
                if test_func():
                    passed += 1
                time.sleep(0.5)  # Small delay between tests
            except Exception as e:
                print(f"❌ {test_name} failed with exception: {e}")
        
        print(f"\n📋 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! The API is working correctly.")
            return True
        else:
            print("⚠️  Some tests failed. Check the application setup.")
            return False


def main():
    """Main function to run the API tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test the Cloud Risk Prioritization Engine API")
    parser.add_argument("--url", default="http://localhost:5000", 
                       help="Base URL of the application (default: http://localhost:5000)")
    parser.add_argument("--wait", type=int, default=0,
                       help="Seconds to wait before starting tests (useful if starting app)")
    
    args = parser.parse_args()
    
    if args.wait > 0:
        print(f"⏳ Waiting {args.wait} seconds for application to start...")
        time.sleep(args.wait)
    
    tester = APITester(args.url)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()