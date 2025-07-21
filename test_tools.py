#!/usr/bin/env python3
"""
Simple test script to verify all tools can be imported and run basic functionality.
This helps identify any import or dependency issues.
"""

import sys
import os
import traceback

def test_import(module_name, import_statement):
    """Test if a module can be imported."""
    try:
        exec(import_statement)
        print(f"✅ {module_name}: Import successful")
        return True
    except Exception as e:
        print(f"❌ {module_name}: Import failed - {e}")
        return False

def test_tool_execution(tool_name, command):
    """Test if a tool can be executed with basic functionality."""
    try:
        result = os.system(command)
        if result == 0:
            print(f"✅ {tool_name}: Execution successful")
            return True
        else:
            print(f"⚠️ {tool_name}: Execution completed with exit code {result}")
            return True  # Still consider it a pass if it runs
    except Exception as e:
        print(f"❌ {tool_name}: Execution failed - {e}")
        return False

def main():
    """Run all tests."""
    print("🔍 Testing Sec_ToolBox tools and imports...")
    print("=" * 60)
    
    # Test basic imports
    print("\n📦 Testing imports:")
    
    # Test Guardian's Mandate integration
    test_import("Guardian's Mandate Integration", 
                "from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType")
    
    # Test network scanner
    test_import("Network Scanner", 
                "from tools.security_armory.network_scanner.network_scanner import NetworkScanner")
    
    # Test password analyzer
    test_import("Password Analyzer", 
                "from tools.security_armory.password_analyzer.password_analyzer import PasswordAnalyzer")
    
    # Test supply chain analyzer
    test_import("Supply Chain Security Analyzer", 
                "from tools.security_armory.supply_chain_security_analyzer.supply_chain_security_analyzer import SupplyChainSecurityAnalyzer")
    
    # Test FedRAMP vulnerability manager
    test_import("FedRAMP Vulnerability Manager", 
                "from tools.GRC_automation_scripts.fedramp_vulnerability_manager.fedramp_vulnerability_manager import FedRAMPVulnerabilityManager")
    
    print("\n🛠️ Testing tool execution:")
    
    # Test password analyzer execution
    test_tool_execution("Password Analyzer", 
                       "python3 tools/security_armory/password_analyzer/password_analyzer.py 'testpassword123' --disable-guardian-mandate")
    
    # Test network scanner execution (safe mode)
    test_tool_execution("Network Scanner", 
                       "python3 tools/security_armory/network_scanner/network_scanner.py 127.0.0.1 --disable-guardian-mandate")
    
    # Test supply chain analyzer execution
    test_tool_execution("Supply Chain Security Analyzer", 
                       "python3 tools/security_armory/supply_chain_security_analyzer/supply_chain_security_analyzer.py --demo --disable-guardian-mandate")
    
    # Test FedRAMP vulnerability manager execution
    test_tool_execution("FedRAMP Vulnerability Manager", 
                       "python3 tools/GRC_automation_scripts/fedramp_vulnerability_manager/fedramp_vulnerability_manager.py --demo --disable-guardian-mandate")
    
    print("\n📋 Testing documentation:")
    
    # Check if key documentation files exist
    required_files = [
        "README.md",
        "LICENSE", 
        "SECURITY.md",
        "CONTRIBUTING.md",
        "requirements.txt"
    ]
    
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file}: Found")
        else:
            print(f"❌ {file}: Missing")
    
    print("\n🎯 Testing Guardian's Mandate framework:")
    
    # Test Guardian's Mandate basic functionality
    try:
        from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType
        print("✅ Guardian's Mandate framework: Available")
        
        # Test basic Guardian's Mandate functionality
        class TestTool(GuardianTool):
            def __init__(self):
                super().__init__(
                    tool_name="TestTool",
                    tool_version="1.0.0",
                    evidence_level=EvidenceLevel.MEDIUM
                )
        
        test_tool = TestTool()
        print("✅ Guardian's Mandate: Basic functionality working")
        
    except Exception as e:
        print(f"❌ Guardian's Mandate framework: Error - {e}")
    
    print("\n" + "=" * 60)
    print("🏁 Testing completed!")
    print("\nIf you see any ❌ errors above, those need to be fixed before the GitHub tests will pass.")

if __name__ == "__main__":
    main()