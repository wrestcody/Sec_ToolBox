#!/usr/bin/env python3
"""
Test script for The Guardian's Mandate framework

This script demonstrates the integration of The Guardian's Mandate with the
IAM Anomaly Detector, showing cryptographic integrity, chain of custody,
and forensic export capabilities.
"""

import os
import sys
import json
import tempfile
from datetime import datetime, timedelta

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_guardian_mandate_framework():
    """Test the core Guardian's Mandate framework."""
    print("🛡️  Testing The Guardian's Mandate Framework")
    print("=" * 50)
    
    try:
        from guardians_mandate import (
            GuardianLedger,
            EvidenceLevel,
            AuditEventType,
            record_guardian_event,
            verify_guardian_integrity,
            export_guardian_forensic_data
        )
        print("✅ Guardian's Mandate framework imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import Guardian's Mandate framework: {e}")
        print("Please install dependencies: pip install -r guardians_mandate_requirements.txt")
        return False
    
    # Test 1: Initialize Guardian Ledger
    print("\n1. Testing Guardian Ledger Initialization...")
    try:
        ledger = GuardianLedger(ledger_path="test_guardian_ledger")
        print("✅ Guardian Ledger initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize Guardian Ledger: {e}")
        return False
    
    # Test 2: Record Events
    print("\n2. Testing Event Recording...")
    try:
        event_id1 = ledger.record_event(
            event_type=AuditEventType.SYSTEM_EVENT.value,
            user_id="test_user",
            session_id="test_session_123",
            source_ip="192.168.1.100",
            user_agent="TestApp/1.0",
            action="test_action",
            resource="/test/resource",
            details={"test": "data", "timestamp": datetime.now().isoformat()},
            evidence_level=EvidenceLevel.CRITICAL
        )
        print(f"✅ Event 1 recorded with ID: {event_id1}")
        
        event_id2 = ledger.record_event(
            event_type=AuditEventType.SECURITY_EVENT.value,
            user_id="test_user",
            session_id="test_session_123",
            source_ip="192.168.1.100",
            user_agent="TestApp/1.0",
            action="security_check",
            resource="/test/security",
            details={"security_level": "high", "check_type": "integrity"},
            evidence_level=EvidenceLevel.CRITICAL,
            parent_event_id=event_id1
        )
        print(f"✅ Event 2 recorded with ID: {event_id2}")
        
    except Exception as e:
        print(f"❌ Failed to record events: {e}")
        return False
    
    # Test 3: Verify Integrity
    print("\n3. Testing Integrity Verification...")
    try:
        integrity_result = ledger.verify_integrity()
        if integrity_result['verified']:
            print("✅ Integrity verification PASSED")
            print(f"   Verified blocks: {integrity_result['verified_blocks']}/{integrity_result['total_blocks']}")
        else:
            print("❌ Integrity verification FAILED")
            print(f"   Errors: {integrity_result['errors']}")
            return False
    except Exception as e:
        print(f"❌ Failed to verify integrity: {e}")
        return False
    
    # Test 4: Export Forensic Data
    print("\n4. Testing Forensic Export...")
    try:
        export_path = ledger.export_forensic_data("test_forensic_export.json")
        print(f"✅ Forensic data exported to: {export_path}")
        
        # Verify export file exists and is valid JSON
        with open(export_path, 'r') as f:
            export_data = json.load(f)
        
        if 'export_metadata' in export_data and 'blocks' in export_data:
            print("✅ Export file is valid and contains expected data")
        else:
            print("❌ Export file is missing expected data")
            return False
            
    except Exception as e:
        print(f"❌ Failed to export forensic data: {e}")
        return False
    
    # Test 5: Chain of Custody
    print("\n5. Testing Chain of Custody...")
    try:
        chain = ledger.get_chain_of_custody(event_id2)
        if len(chain) >= 2:  # Should have at least 2 events (parent and child)
            print(f"✅ Chain of custody verified: {len(chain)} events in chain")
            for i, event in enumerate(chain):
                print(f"   {i+1}. Event ID: {event['event']['event_id']}")
                print(f"      Type: {event['event']['event_type']}")
                print(f"      Action: {event['event']['action']}")
        else:
            print("❌ Chain of custody verification failed")
            return False
    except Exception as e:
        print(f"❌ Failed to verify chain of custody: {e}")
        return False
    
    print("\n✅ All Guardian's Mandate framework tests PASSED!")
    return True


def test_iam_anomaly_detector_integration():
    """Test the IAM Anomaly Detector with Guardian's Mandate integration."""
    print("\n🔍 Testing IAM Anomaly Detector with Guardian's Mandate")
    print("=" * 60)
    
    try:
        # Import the IAM Anomaly Detector
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools', 'cloud_configuration_auditors', 'iam_anomaly_detector'))
        from iam_anomaly_detector import IAMAnomalyDetector
        print("✅ IAM Anomaly Detector imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import IAM Anomaly Detector: {e}")
        return False
    
    # Create a simple test CloudTrail log
    print("\n1. Creating test CloudTrail logs...")
    test_logs = {
        "Records": [
            {
                "eventTime": (datetime.now() - timedelta(days=2)).isoformat() + "Z",
                "userIdentity": {"userName": "test_user_1"},
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "192.168.1.100",
                "awsRegion": "us-east-1"
            },
            {
                "eventTime": (datetime.now() - timedelta(days=1)).isoformat() + "Z",
                "userIdentity": {"userName": "test_user_1"},
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "192.168.1.100",
                "awsRegion": "us-east-1"
            },
            {
                "eventTime": datetime.now().isoformat() + "Z",
                "userIdentity": {"userName": "test_user_1"},
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "10.0.0.50",  # Different IP - should trigger anomaly
                "awsRegion": "us-west-2"  # Different region - should trigger anomaly
            }
        ]
    }
    
    # Write test logs to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_logs, f)
        test_log_file = f.name
    
    try:
        print(f"✅ Test logs created: {test_log_file}")
        
        # Test 2: Initialize IAM Anomaly Detector with Guardian's Mandate
        print("\n2. Initializing IAM Anomaly Detector with Guardian's Mandate...")
        detector = IAMAnomalyDetector(
            baseline_days=30,
            enable_guardian_mandate=True
        )
        print("✅ IAM Anomaly Detector initialized with Guardian's Mandate")
        
        # Test 3: Run Analysis
        print("\n3. Running anomaly detection analysis...")
        detector.run_analysis(
            log_file=test_log_file,
            detection_days=1,
            output_format='console'
        )
        print("✅ Anomaly detection analysis completed")
        
        # Test 4: Verify Guardian's Mandate Integration
        print("\n4. Verifying Guardian's Mandate integration...")
        if hasattr(detector, 'guardian_ledger') and detector.guardian_ledger:
            integrity_result = detector.guardian_ledger.verify_integrity()
            if integrity_result['verified']:
                print("✅ Guardian's Mandate integration verified")
                print(f"   Total events recorded: {integrity_result['total_blocks']}")
            else:
                print("❌ Guardian's Mandate integration verification failed")
                return False
        else:
            print("❌ Guardian's Mandate not properly integrated")
            return False
            
    except Exception as e:
        print(f"❌ Failed to run IAM anomaly detection: {e}")
        return False
    finally:
        # Clean up test file
        try:
            os.unlink(test_log_file)
        except:
            pass
    
    print("\n✅ All IAM Anomaly Detector integration tests PASSED!")
    return True


def test_compliance_features():
    """Test compliance-related features."""
    print("\n📋 Testing Compliance Features")
    print("=" * 40)
    
    try:
        from guardians_mandate import GuardianLedger, EvidenceLevel, AuditEventType
        
        ledger = GuardianLedger(ledger_path="test_compliance_ledger")
        
        # Test SOC2 compliance events
        print("\n1. Testing SOC2 compliance events...")
        soc2_event_id = ledger.record_event(
            event_type=AuditEventType.DATA_ACCESS.value,
            user_id="compliance_user",
            session_id="compliance_session",
            source_ip="192.168.1.200",
            user_agent="ComplianceApp/1.0",
            action="access_control_check",
            resource="/compliance/soc2",
            details={
                "compliance_framework": "SOC2",
                "control": "CC6.1",
                "description": "Logical and physical access controls",
                "status": "COMPLIANT"
            },
            evidence_level=EvidenceLevel.CRITICAL
        )
        print(f"✅ SOC2 compliance event recorded: {soc2_event_id}")
        
        # Test ISO27001 compliance events
        print("\n2. Testing ISO27001 compliance events...")
        iso_event_id = ledger.record_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE.value,
            user_id="compliance_user",
            session_id="compliance_session",
            source_ip="192.168.1.200",
            user_agent="ComplianceApp/1.0",
            action="access_rights_management",
            resource="/compliance/iso27001",
            details={
                "compliance_framework": "ISO27001",
                "control": "A.9.2.3",
                "description": "Access rights management",
                "status": "COMPLIANT"
            },
            evidence_level=EvidenceLevel.CRITICAL
        )
        print(f"✅ ISO27001 compliance event recorded: {iso_event_id}")
        
        # Test NIST compliance events
        print("\n3. Testing NIST compliance events...")
        nist_event_id = ledger.record_event(
            event_type=AuditEventType.SECURITY_EVENT.value,
            user_id="compliance_user",
            session_id="compliance_session",
            source_ip="192.168.1.200",
            user_agent="ComplianceApp/1.0",
            action="audit_review",
            resource="/compliance/nist",
            details={
                "compliance_framework": "NIST",
                "control": "AU-6",
                "description": "Audit Review, Analysis, and Reporting",
                "status": "COMPLIANT"
            },
            evidence_level=EvidenceLevel.CRITICAL
        )
        print(f"✅ NIST compliance event recorded: {nist_event_id}")
        
        # Verify all compliance events
        integrity_result = ledger.verify_integrity()
        if integrity_result['verified']:
            print(f"\n✅ All compliance events verified: {integrity_result['total_blocks']} events recorded")
        else:
            print("❌ Compliance events verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Failed to test compliance features: {e}")
        return False
    
    print("\n✅ All compliance feature tests PASSED!")
    return True


def main():
    """Main test function."""
    print("🧪 The Guardian's Mandate - Comprehensive Test Suite")
    print("=" * 60)
    
    # Run all tests
    tests = [
        ("Guardian's Mandate Framework", test_guardian_mandate_framework),
        ("IAM Anomaly Detector Integration", test_iam_anomaly_detector_integration),
        ("Compliance Features", test_compliance_features)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests PASSED! The Guardian's Mandate is working correctly.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())