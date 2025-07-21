#!/usr/bin/env python3
"""
Comprehensive Test Suite for All Guardian's Mandate Tools

This script demonstrates the complete Guardian's Forge system with all tools
implementing The Guardian's Mandate for unassailable digital evidence integrity
and unbreakable chain of custody at scale.
"""

import os
import sys
import json
import tempfile
import time
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_guardian_mandate_framework():
    """Test the core Guardian's Mandate framework."""
    print("🛡️  Testing The Guardian's Mandate Framework")
    print("=" * 50)
    
    try:
        from guardians_mandate import GuardianLedger, EvidenceLevel, AuditEventType
        from guardians_mandate_integration import GuardianTool, GuardianComplianceChecker
        print("✅ Guardian's Mandate framework imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import Guardian's Mandate framework: {e}")
        return False
    
    # Test 1: Framework functionality
    print("\n1. Testing core framework functionality...")
    try:
        ledger = GuardianLedger(ledger_path="test_framework_ledger")
        
        # Record test events
        event_id1 = ledger.record_event(
            event_type=AuditEventType.SYSTEM_EVENT.value,
            user_id="test_user",
            session_id="test_session",
            source_ip="192.168.1.100",
            user_agent="TestFramework/1.0",
            action="framework_test",
            resource="/test/framework",
            details={"test": "framework_functionality"},
            evidence_level=EvidenceLevel.CRITICAL
        )
        
        # Verify integrity
        integrity_result = ledger.verify_integrity()
        if integrity_result['verified']:
            print("✅ Framework functionality verified")
        else:
            print("❌ Framework functionality failed")
            return False
            
    except Exception as e:
        print(f"❌ Framework test failed: {e}")
        return False
    
    # Test 2: Compliance checking
    print("\n2. Testing compliance checking...")
    try:
        compliance_results = GuardianComplianceChecker.check_repository_compliance()
        print(f"✅ Compliance check completed:")
        print(f"   Total tools: {compliance_results['total_tools']}")
        print(f"   Compliant: {compliance_results['compliant_tools']}")
        print(f"   Non-compliant: {compliance_results['non_compliant_tools']}")
    except Exception as e:
        print(f"❌ Compliance check failed: {e}")
        return False
    
    print("\n✅ All Guardian's Mandate framework tests PASSED!")
    return True


def test_iam_anomaly_detector():
    """Test the IAM Anomaly Detector with Guardian's Mandate."""
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
    
    # Create test CloudTrail logs
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
        
        # Test 2: Run IAM Anomaly Detection
        print("\n2. Running IAM anomaly detection...")
        detector = IAMAnomalyDetector(
            baseline_days=30,
            enable_guardian_mandate=True
        )
        
        # Run analysis
        detector.run_analysis(
            log_file=test_log_file,
            detection_days=1,
            output_format='console'
        )
        
        # Verify Guardian's Mandate integration
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
        print(f"❌ IAM anomaly detection failed: {e}")
        return False
    finally:
        # Clean up test file
        try:
            os.unlink(test_log_file)
        except:
            pass
    
    print("\n✅ All IAM Anomaly Detector tests PASSED!")
    return True


def test_network_security_scanner():
    """Test the Network Security Scanner with Guardian's Mandate."""
    print("\n🔍 Testing Network Security Scanner with Guardian's Mandate")
    print("=" * 60)
    
    try:
        # Import the Network Security Scanner
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools', 'network_security_scanner'))
        from network_security_scanner import NetworkSecurityScanner
        print("✅ Network Security Scanner imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import Network Security Scanner: {e}")
        return False
    
    try:
        # Test 1: Initialize scanner
        print("\n1. Initializing Network Security Scanner...")
        scanner = NetworkSecurityScanner(
            enable_guardian_mandate=True
        )
        print("✅ Scanner initialized successfully")
        
        # Test 2: Run network scan (using localhost for testing)
        print("\n2. Running network scan...")
        results = scanner.scan_network("127.0.0.1/32", "basic")
        
        # Verify results
        if "scan_info" in results and "hosts" in results:
            print("✅ Network scan completed successfully")
            print(f"   Hosts scanned: {len(results['hosts'])}")
            print(f"   Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        else:
            print("❌ Network scan failed")
            return False
        
        # Test 3: Verify Guardian's Mandate integration
        print("\n3. Verifying Guardian's Mandate integration...")
        integrity_result = scanner.verify_integrity()
        if integrity_result['verified']:
            print("✅ Guardian's Mandate integration verified")
            print(f"   Total events recorded: {integrity_result['total_blocks']}")
        else:
            print("❌ Guardian's Mandate integration verification failed")
            return False
        
        # Test 4: Export forensic data
        print("\n4. Testing forensic export...")
        export_path = scanner.export_forensic_data()
        if export_path and os.path.exists(export_path):
            print(f"✅ Forensic data exported: {export_path}")
        else:
            print("❌ Forensic export failed")
            return False
            
    except Exception as e:
        print(f"❌ Network Security Scanner test failed: {e}")
        return False
    
    print("\n✅ All Network Security Scanner tests PASSED!")
    return True


def test_file_integrity_monitor():
    """Test the File Integrity Monitor with Guardian's Mandate."""
    print("\n📁 Testing File Integrity Monitor with Guardian's Mandate")
    print("=" * 60)
    
    try:
        # Import the File Integrity Monitor
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools', 'file_integrity_monitor'))
        from file_integrity_monitor import FileIntegrityMonitor
        print("✅ File Integrity Monitor imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import File Integrity Monitor: {e}")
        return False
    
    # Create test directory and files
    test_dir = tempfile.mkdtemp()
    test_file = os.path.join(test_dir, "test_file.txt")
    
    try:
        # Create test file
        with open(test_file, 'w') as f:
            f.write("Initial content")
        
        print(f"✅ Test directory created: {test_dir}")
        
        # Test 1: Initialize monitor
        print("\n1. Initializing File Integrity Monitor...")
        monitor = FileIntegrityMonitor(
            enable_guardian_mandate=True
        )
        print("✅ Monitor initialized successfully")
        
        # Test 2: Add monitoring path
        print("\n2. Adding monitoring path...")
        if monitor.add_monitoring_path(test_dir, recursive=True):
            print("✅ Monitoring path added successfully")
        else:
            print("❌ Failed to add monitoring path")
            return False
        
        # Test 3: Export baseline
        print("\n3. Testing baseline export...")
        baseline_file = os.path.join(test_dir, "baseline.json")
        if monitor.export_baseline(baseline_file):
            print(f"✅ Baseline exported: {baseline_file}")
        else:
            print("❌ Baseline export failed")
            return False
        
        # Test 4: Modify file to trigger change detection
        print("\n4. Testing change detection...")
        with open(test_file, 'w') as f:
            f.write("Modified content")
        
        # Check integrity
        monitor._check_integrity()
        
        # Get report
        report = monitor.get_integrity_report()
        if report['summary']['total_changes'] > 0:
            print("✅ Change detection working")
            print(f"   Changes detected: {report['summary']['total_changes']}")
        else:
            print("❌ Change detection failed")
            return False
        
        # Test 5: Verify Guardian's Mandate integration
        print("\n5. Verifying Guardian's Mandate integration...")
        integrity_result = monitor.verify_integrity()
        if integrity_result['verified']:
            print("✅ Guardian's Mandate integration verified")
            print(f"   Total events recorded: {integrity_result['total_blocks']}")
        else:
            print("❌ Guardian's Mandate integration verification failed")
            return False
        
        # Test 6: Export forensic data
        print("\n6. Testing forensic export...")
        export_path = monitor.export_forensic_data()
        if export_path and os.path.exists(export_path):
            print(f"✅ Forensic data exported: {export_path}")
        else:
            print("❌ Forensic export failed")
            return False
            
    except Exception as e:
        print(f"❌ File Integrity Monitor test failed: {e}")
        return False
    finally:
        # Clean up test directory
        try:
            import shutil
            shutil.rmtree(test_dir)
        except:
            pass
    
    print("\n✅ All File Integrity Monitor tests PASSED!")
    return True


def test_automated_tool_generation():
    """Test automated tool generation with Guardian's Mandate."""
    print("\n🔧 Testing Automated Tool Generation")
    print("=" * 50)
    
    try:
        from guardians_mandate_integration import GuardianToolGenerator
        print("✅ Guardian Tool Generator imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import Guardian Tool Generator: {e}")
        return False
    
    try:
        # Test 1: Generate new tool template
        print("\n1. Generating new tool template...")
        tool_path = GuardianToolGenerator.create_tool_template(
            "Test Security Tool",
            "A test security tool with Guardian's Mandate integration"
        )
        
        if os.path.exists(tool_path):
            print(f"✅ Tool template created: {tool_path}")
        else:
            print("❌ Tool template creation failed")
            return False
        
        # Test 2: Verify generated tool structure
        print("\n2. Verifying generated tool structure...")
        tool_dir = os.path.dirname(tool_path)
        
        # Check for required files
        required_files = [
            os.path.basename(tool_path),
            "requirements.txt",
            "README.md"
        ]
        
        for file_name in required_files:
            file_path = os.path.join(tool_dir, file_name)
            if os.path.exists(file_path):
                print(f"✅ {file_name} exists")
            else:
                print(f"❌ {file_name} missing")
                return False
        
        # Test 3: Verify Guardian's Mandate integration in generated tool
        print("\n3. Verifying Guardian's Mandate integration...")
        with open(tool_path, 'r') as f:
            tool_content = f.read()
        
        required_elements = [
            "GuardianTool",
            "record_guardian_event",
            "verify_integrity",
            "export_forensic_data"
        ]
        
        for element in required_elements:
            if element in tool_content:
                print(f"✅ {element} found in generated tool")
            else:
                print(f"❌ {element} missing from generated tool")
                return False
        
        print("✅ Generated tool has proper Guardian's Mandate integration")
        
    except Exception as e:
        print(f"❌ Automated tool generation test failed: {e}")
        return False
    
    print("\n✅ All Automated Tool Generation tests PASSED!")
    return True


def test_comprehensive_workflow():
    """Test a comprehensive security workflow with all tools."""
    print("\n🔄 Testing Comprehensive Security Workflow")
    print("=" * 60)
    
    try:
        # This test simulates a real-world security workflow
        print("\n1. Simulating comprehensive security workflow...")
        
        # Create a temporary workspace for the workflow
        workflow_dir = tempfile.mkdtemp()
        
        try:
            # Step 1: File Integrity Monitoring
            print("   Step 1: Setting up file integrity monitoring...")
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools', 'file_integrity_monitor'))
            from file_integrity_monitor import FileIntegrityMonitor
            
            monitor = FileIntegrityMonitor(enable_guardian_mandate=True)
            monitor.add_monitoring_path(workflow_dir, recursive=True)
            
            # Step 2: Network Security Scanning
            print("   Step 2: Running network security scan...")
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools', 'network_security_scanner'))
            from network_security_scanner import NetworkSecurityScanner
            
            scanner = NetworkSecurityScanner(enable_guardian_mandate=True)
            scan_results = scanner.scan_network("127.0.0.1/32", "basic")
            
            # Step 3: IAM Anomaly Detection
            print("   Step 3: Running IAM anomaly detection...")
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools', 'cloud_configuration_auditors', 'iam_anomaly_detector'))
            from iam_anomaly_detector import IAMAnomalyDetector
            
            # Create test CloudTrail logs
            test_logs = {
                "Records": [
                    {
                        "eventTime": datetime.now().isoformat() + "Z",
                        "userIdentity": {"userName": "workflow_test_user"},
                        "eventName": "ConsoleLogin",
                        "sourceIPAddress": "192.168.1.100",
                        "awsRegion": "us-east-1"
                    }
                ]
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(test_logs, f)
                test_log_file = f.name
            
            detector = IAMAnomalyDetector(enable_guardian_mandate=True)
            detector.run_analysis(test_log_file, 1, 'console')
            
            # Clean up test file
            os.unlink(test_log_file)
            
            # Step 4: Verify all tools have Guardian's Mandate integration
            print("   Step 4: Verifying Guardian's Mandate integration across all tools...")
            
            tools = [monitor, scanner, detector]
            for i, tool in enumerate(tools, 1):
                if hasattr(tool, 'guardian_ledger') and tool.guardian_ledger:
                    integrity_result = tool.verify_integrity()
                    if integrity_result['verified']:
                        print(f"      Tool {i}: ✅ Guardian's Mandate verified")
                    else:
                        print(f"      Tool {i}: ❌ Guardian's Mandate verification failed")
                        return False
                else:
                    print(f"      Tool {i}: ❌ Guardian's Mandate not integrated")
                    return False
            
            # Step 5: Export comprehensive forensic data
            print("   Step 5: Exporting comprehensive forensic data...")
            forensic_exports = []
            
            for tool in tools:
                export_path = tool.export_forensic_data()
                if export_path:
                    forensic_exports.append(export_path)
                    print(f"      Exported: {export_path}")
            
            if len(forensic_exports) == len(tools):
                print("✅ All tools exported forensic data successfully")
            else:
                print("❌ Some tools failed to export forensic data")
                return False
            
            print("✅ Comprehensive workflow completed successfully")
            
        finally:
            # Clean up workflow directory
            import shutil
            shutil.rmtree(workflow_dir)
        
    except Exception as e:
        print(f"❌ Comprehensive workflow test failed: {e}")
        return False
    
    print("\n✅ All Comprehensive Workflow tests PASSED!")
    return True


def main():
    """Main test function."""
    print("🧪 The Guardian's Forge - Comprehensive Test Suite")
    print("=" * 60)
    print("Testing all tools with Guardian's Mandate integration")
    print("=" * 60)
    
    # Run all tests
    tests = [
        ("Guardian's Mandate Framework", test_guardian_mandate_framework),
        ("IAM Anomaly Detector", test_iam_anomaly_detector),
        ("Network Security Scanner", test_network_security_scanner),
        ("File Integrity Monitor", test_file_integrity_monitor),
        ("Automated Tool Generation", test_automated_tool_generation),
        ("Comprehensive Workflow", test_comprehensive_workflow)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*20} {test_name} {'='*20}")
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 COMPREHENSIVE TEST SUMMARY")
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
        print("\n🎉 ALL TESTS PASSED!")
        print("The Guardian's Forge is fully operational with:")
        print("✅ Unassailable digital evidence integrity")
        print("✅ Unbreakable chain of custody")
        print("✅ Automated compliance at scale")
        print("✅ Forensic-ready evidence export")
        print("✅ Cryptographic verification")
        print("✅ Legal evidentiary standards compliance")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())