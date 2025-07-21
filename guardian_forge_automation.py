#!/usr/bin/env python3
"""
Guardian's Forge Automation System

This script ensures that ALL tools in The Guardian's Forge automatically implement
The Guardian's Mandate for unassailable digital evidence integrity and unbreakable
chain of custody at scale.

Features:
- Automated Guardian's Mandate integration for new tools
- Compliance checking and enforcement
- Automated testing and validation
- Deployment automation
- Continuous monitoring of tool compliance
"""

import os
import sys
import json
import subprocess
import argparse
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from guardians_mandate_integration import (
        GuardianComplianceChecker,
        GuardianToolGenerator,
        GuardianTool
    )
    GUARDIAN_INTEGRATION_AVAILABLE = True
except ImportError:
    print("Warning: Guardian's Mandate integration not available.")
    GUARDIAN_INTEGRATION_AVAILABLE = False


class GuardianForgeAutomation:
    """
    Automation system for ensuring all tools implement The Guardian's Mandate.
    """
    
    def __init__(self, repo_path: str = "."):
        """
        Initialize the Guardian's Forge automation system.
        
        Args:
            repo_path: Path to the repository root
        """
        self.repo_path = Path(repo_path)
        self.tools_path = self.repo_path / "tools"
        self.setup_logging()
        
        # Ensure tools directory exists
        self.tools_path.mkdir(exist_ok=True)
    
    def setup_logging(self):
        """Setup logging for the automation system."""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("guardian_forge_automation.log")
            ]
        )
        self.logger = logging.getLogger("GuardianForgeAutomation")
    
    def scan_for_tools(self) -> List[Path]:
        """
        Scan the repository for all security tools.
        
        Returns:
            List of tool paths
        """
        tools = []
        
        if self.tools_path.exists():
            for py_file in self.tools_path.rglob("*.py"):
                if py_file.name != "__init__.py" and py_file.name.endswith(".py"):
                    tools.append(py_file)
        
        return tools
    
    def check_tool_compliance(self, tool_path: Path) -> Dict[str, Any]:
        """
        Check if a tool complies with Guardian's Mandate requirements.
        
        Args:
            tool_path: Path to the tool to check
            
        Returns:
            Compliance check results
        """
        if not GUARDIAN_INTEGRATION_AVAILABLE:
            return {
                "tool_path": str(tool_path),
                "compliant": False,
                "issues": ["Guardian's Mandate integration not available"],
                "recommendations": ["Install Guardian's Mandate framework"]
            }
        
        return GuardianComplianceChecker.check_tool_compliance(str(tool_path))
    
    def enforce_guardian_mandate(self, tool_path: Path) -> bool:
        """
        Enforce Guardian's Mandate integration on a tool.
        
        Args:
            tool_path: Path to the tool to enforce
            
        Returns:
            True if enforcement was successful
        """
        try:
            self.logger.info(f"Enforcing Guardian's Mandate on {tool_path}")
            
            # Read the tool file
            with open(tool_path, 'r') as f:
                content = f.read()
            
            # Check if already has Guardian's Mandate
            if "GuardianTool" in content:
                self.logger.info(f"Tool {tool_path} already has Guardian's Mandate")
                return True
            
            # Add Guardian's Mandate integration
            modified_content = self._add_guardian_mandate_integration(content, tool_path)
            
            # Write back the modified content
            with open(tool_path, 'w') as f:
                f.write(modified_content)
            
            self.logger.info(f"Successfully enforced Guardian's Mandate on {tool_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to enforce Guardian's Mandate on {tool_path}: {e}")
            return False
    
    def _add_guardian_mandate_integration(self, content: str, tool_path: Path) -> str:
        """
        Add Guardian's Mandate integration to tool content.
        
        Args:
            content: Original tool content
            tool_path: Path to the tool file
            
        Returns:
            Modified content with Guardian's Mandate integration
        """
        # Add import statement
        import_statement = """
# Import Guardian's Mandate integration
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType

"""
        
        # Find the right place to insert the import
        lines = content.split('\n')
        
        # Find the first class definition
        class_index = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('class ') and ':' in line:
                class_index = i
                break
        
        if class_index == -1:
            # No class found, add at the beginning
            lines.insert(0, import_statement)
        else:
            # Add before the first class
            lines.insert(class_index, import_statement)
        
        # Find the main class and modify it
        for i, line in enumerate(lines):
            if line.strip().startswith('class ') and ':' in line:
                # Check if it's not already a GuardianTool
                if 'GuardianTool' not in line:
                    # Modify the class definition
                    class_name = line.split('class ')[1].split('(')[0].split(':')[0].strip()
                    lines[i] = f"class {class_name}(GuardianTool):"
                    
                    # Find the __init__ method and modify it
                    for j in range(i + 1, len(lines)):
                        if 'def __init__' in lines[j]:
                            # Add Guardian's Mandate initialization
                            indent = len(lines[j]) - len(lines[j].lstrip())
                            guardian_init = ' ' * indent + "super().__init__(\n"
                            guardian_init += ' ' * (indent + 4) + f'tool_name="{class_name}",\n'
                            guardian_init += ' ' * (indent + 4) + 'tool_version="1.0.0",\n'
                            guardian_init += ' ' * (indent + 4) + 'evidence_level=EvidenceLevel.HIGH\n'
                            guardian_init += ' ' * indent + ")\n"
                            
                            # Insert after the __init__ line
                            lines.insert(j + 1, guardian_init)
                            break
                    break
        
        return '\n'.join(lines)
    
    def create_new_tool(self, tool_name: str, tool_description: str, tool_type: str = "security") -> Optional[Path]:
        """
        Create a new security tool with automatic Guardian's Mandate integration.
        
        Args:
            tool_name: Name of the new tool
            tool_description: Description of the tool's purpose
            tool_type: Type of tool (security, monitoring, analysis, etc.)
            
        Returns:
            Path to the created tool, or None if creation failed
        """
        try:
            if not GUARDIAN_INTEGRATION_AVAILABLE:
                self.logger.error("Guardian's Mandate integration not available")
                return None
            
            # Create tool using the generator
            tool_path = GuardianToolGenerator.create_tool_template(
                tool_name=tool_name,
                tool_description=tool_description,
                output_dir=str(self.tools_path / tool_type)
            )
            
            self.logger.info(f"Created new tool: {tool_path}")
            return Path(tool_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create new tool: {e}")
            return None
    
    def run_compliance_check(self) -> Dict[str, Any]:
        """
        Run a comprehensive compliance check on all tools.
        
        Returns:
            Compliance check results
        """
        self.logger.info("Running comprehensive compliance check...")
        
        if not GUARDIAN_INTEGRATION_AVAILABLE:
            return {
                "status": "error",
                "message": "Guardian's Mandate integration not available",
                "total_tools": 0,
                "compliant_tools": 0,
                "non_compliant_tools": 0
            }
        
        return GuardianComplianceChecker.check_repository_compliance(str(self.repo_path))
    
    def enforce_compliance_on_all_tools(self) -> Dict[str, Any]:
        """
        Enforce Guardian's Mandate compliance on all tools in the repository.
        
        Returns:
            Enforcement results
        """
        self.logger.info("Enforcing compliance on all tools...")
        
        tools = self.scan_for_tools()
        results = {
            "total_tools": len(tools),
            "enforced": 0,
            "already_compliant": 0,
            "failed": 0,
            "details": []
        }
        
        for tool_path in tools:
            compliance_result = self.check_tool_compliance(tool_path)
            
            if compliance_result["compliant"]:
                results["already_compliant"] += 1
                results["details"].append({
                    "tool": str(tool_path),
                    "status": "already_compliant"
                })
            else:
                if self.enforce_guardian_mandate(tool_path):
                    results["enforced"] += 1
                    results["details"].append({
                        "tool": str(tool_path),
                        "status": "enforced"
                    })
                else:
                    results["failed"] += 1
                    results["details"].append({
                        "tool": str(tool_path),
                        "status": "failed"
                    })
        
        return results
    
    def run_automated_tests(self) -> Dict[str, Any]:
        """
        Run automated tests on all tools.
        
        Returns:
            Test results
        """
        self.logger.info("Running automated tests...")
        
        results = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "details": []
        }
        
        try:
            # Run the comprehensive test suite
            test_script = self.repo_path / "test_all_guardian_tools.py"
            if test_script.exists():
                result = subprocess.run(
                    [sys.executable, str(test_script)],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes timeout
                )
                
                results["total_tests"] = 1
                if result.returncode == 0:
                    results["passed"] = 1
                    results["details"].append({
                        "test": "comprehensive_test_suite",
                        "status": "passed",
                        "output": result.stdout
                    })
                else:
                    results["failed"] = 1
                    results["details"].append({
                        "test": "comprehensive_test_suite",
                        "status": "failed",
                        "output": result.stderr
                    })
            
        except Exception as e:
            self.logger.error(f"Failed to run automated tests: {e}")
            results["failed"] = 1
            results["details"].append({
                "test": "automated_tests",
                "status": "error",
                "error": str(e)
            })
        
        return results
    
    def generate_compliance_report(self) -> str:
        """
        Generate a comprehensive compliance report.
        
        Returns:
            Path to the generated report
        """
        self.logger.info("Generating compliance report...")
        
        report_data = {
            "report_info": {
                "generated_at": datetime.now().isoformat(),
                "repository_path": str(self.repo_path),
                "guardian_mandate_version": "1.0.0"
            },
            "compliance_check": self.run_compliance_check(),
            "enforcement_results": self.enforce_compliance_on_all_tools(),
            "test_results": self.run_automated_tests(),
            "tools_inventory": [
                {
                    "path": str(tool_path),
                    "name": tool_path.stem,
                    "type": tool_path.parent.name
                }
                for tool_path in self.scan_for_tools()
            ]
        }
        
        # Write report
        report_path = self.repo_path / "guardian_compliance_report.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Compliance report generated: {report_path}")
        return str(report_path)
    
    def setup_continuous_monitoring(self) -> bool:
        """
        Setup continuous monitoring for tool compliance.
        
        Returns:
            True if setup was successful
        """
        self.logger.info("Setting up continuous monitoring...")
        
        try:
            # Create monitoring script
            monitoring_script = self.repo_path / "guardian_monitor.py"
            
            script_content = f'''#!/usr/bin/env python3
"""
Guardian's Forge Continuous Monitoring

This script continuously monitors all tools for Guardian's Mandate compliance.
"""

import time
import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardian_forge_automation import GuardianForgeAutomation

def main():
    """Main monitoring function."""
    automation = GuardianForgeAutomation()
    
    print("🛡️  Guardian's Forge Continuous Monitoring Started")
    print("=" * 50)
    
    while True:
        try:
            # Run compliance check
            compliance = automation.run_compliance_check()
            
            print(f"\\n[{datetime.now().isoformat()}] Compliance Check:")
            print(f"   Total tools: {{compliance['total_tools']}}")
            print(f"   Compliant: {{compliance['compliant_tools']}}")
            print(f"   Non-compliant: {{compliance['non_compliant_tools']}}")
            
            # Enforce compliance if needed
            if compliance['non_compliant_tools'] > 0:
                print("   🔧 Enforcing compliance...")
                enforcement = automation.enforce_compliance_on_all_tools()
                print(f"   Enforced: {{enforcement['enforced']}}")
                print(f"   Failed: {{enforcement['failed']}}")
            
            # Wait before next check
            time.sleep(300)  # Check every 5 minutes
            
        except KeyboardInterrupt:
            print("\\n🛑 Monitoring stopped by user")
            break
        except Exception as e:
            print(f"\\n❌ Monitoring error: {{e}}")
            time.sleep(60)  # Wait 1 minute before retrying

if __name__ == "__main__":
    main()
'''
            
            with open(monitoring_script, 'w') as f:
                f.write(script_content)
            
            # Make it executable
            os.chmod(monitoring_script, 0o755)
            
            self.logger.info(f"Continuous monitoring script created: {monitoring_script}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup continuous monitoring: {e}")
            return False
    
    def deploy_to_production(self, target_path: str) -> bool:
        """
        Deploy The Guardian's Forge to production.
        
        Args:
            target_path: Target deployment path
            
        Returns:
            True if deployment was successful
        """
        self.logger.info(f"Deploying to production: {target_path}")
        
        try:
            target_path = Path(target_path)
            target_path.mkdir(parents=True, exist_ok=True)
            
            # Copy all necessary files
            files_to_copy = [
                "guardians_mandate.py",
                "guardians_mandate_integration.py",
                "guardians_mandate_requirements.txt",
                "GUARDIANS_MANDATE.md",
                "README.md",
                "test_all_guardian_tools.py",
                "guardian_forge_automation.py"
            ]
            
            for file_name in files_to_copy:
                source_file = self.repo_path / file_name
                if source_file.exists():
                    import shutil
                    shutil.copy2(source_file, target_path / file_name)
            
            # Copy tools directory
            tools_target = target_path / "tools"
            if self.tools_path.exists():
                import shutil
                shutil.copytree(self.tools_path, tools_target, dirs_exist_ok=True)
            
            # Create deployment script
            deploy_script = target_path / "deploy_guardian_forge.sh"
            deploy_content = f'''#!/bin/bash
# Guardian's Forge Deployment Script

echo "🛡️  Deploying The Guardian's Forge..."

# Install dependencies
pip install -r guardians_mandate_requirements.txt

# Run compliance check
python guardian_forge_automation.py --compliance-check

# Run tests
python test_all_guardian_tools.py

# Setup continuous monitoring
python guardian_forge_automation.py --setup-monitoring

echo "✅ Guardian's Forge deployed successfully!"
'''
            
            with open(deploy_script, 'w') as f:
                f.write(deploy_content)
            
            os.chmod(deploy_script, 0o755)
            
            self.logger.info(f"Deployment completed: {target_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            return False


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Guardian's Forge Automation System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --compliance-check
  %(prog)s --enforce-compliance
  %(prog)s --create-tool "Vulnerability Scanner" "Scans for security vulnerabilities"
  %(prog)s --generate-report
  %(prog)s --setup-monitoring
  %(prog)s --deploy /opt/guardian_forge
        """
    )
    
    parser.add_argument(
        '--compliance-check',
        action='store_true',
        help='Run compliance check on all tools'
    )
    
    parser.add_argument(
        '--enforce-compliance',
        action='store_true',
        help='Enforce Guardian\'s Mandate compliance on all tools'
    )
    
    parser.add_argument(
        '--create-tool',
        nargs=2,
        metavar=('NAME', 'DESCRIPTION'),
        help='Create a new tool with Guardian\'s Mandate integration'
    )
    
    parser.add_argument(
        '--generate-report',
        action='store_true',
        help='Generate comprehensive compliance report'
    )
    
    parser.add_argument(
        '--setup-monitoring',
        action='store_true',
        help='Setup continuous monitoring for compliance'
    )
    
    parser.add_argument(
        '--deploy',
        metavar='TARGET_PATH',
        help='Deploy Guardian\'s Forge to production'
    )
    
    parser.add_argument(
        '--run-tests',
        action='store_true',
        help='Run automated tests on all tools'
    )
    
    parser.add_argument(
        '--repo-path',
        default='.',
        help='Path to the repository root (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Initialize automation system
    automation = GuardianForgeAutomation(args.repo_path)
    
    try:
        if args.compliance_check:
            print("🔍 Running compliance check...")
            results = automation.run_compliance_check()
            print(f"Total tools: {results['total_tools']}")
            print(f"Compliant: {results['compliant_tools']}")
            print(f"Non-compliant: {results['non_compliant_tools']}")
        
        elif args.enforce_compliance:
            print("🔧 Enforcing compliance...")
            results = automation.enforce_compliance_on_all_tools()
            print(f"Total tools: {results['total_tools']}")
            print(f"Enforced: {results['enforced']}")
            print(f"Already compliant: {results['already_compliant']}")
            print(f"Failed: {results['failed']}")
        
        elif args.create_tool:
            tool_name, tool_description = args.create_tool
            print(f"🔧 Creating new tool: {tool_name}")
            tool_path = automation.create_new_tool(tool_name, tool_description)
            if tool_path:
                print(f"✅ Tool created: {tool_path}")
            else:
                print("❌ Failed to create tool")
        
        elif args.generate_report:
            print("📊 Generating compliance report...")
            report_path = automation.generate_compliance_report()
            print(f"✅ Report generated: {report_path}")
        
        elif args.setup_monitoring:
            print("🔄 Setting up continuous monitoring...")
            if automation.setup_continuous_monitoring():
                print("✅ Continuous monitoring setup completed")
            else:
                print("❌ Failed to setup continuous monitoring")
        
        elif args.deploy:
            print(f"🚀 Deploying to: {args.deploy}")
            if automation.deploy_to_production(args.deploy):
                print("✅ Deployment completed successfully")
            else:
                print("❌ Deployment failed")
        
        elif args.run_tests:
            print("🧪 Running automated tests...")
            results = automation.run_automated_tests()
            print(f"Total tests: {results['total_tests']}")
            print(f"Passed: {results['passed']}")
            print(f"Failed: {results['failed']}")
        
        else:
            # Default: run comprehensive check and report
            print("🛡️  Guardian's Forge Automation System")
            print("=" * 50)
            
            print("\n1. Running compliance check...")
            compliance = automation.run_compliance_check()
            print(f"   Total tools: {compliance['total_tools']}")
            print(f"   Compliant: {compliance['compliant_tools']}")
            print(f"   Non-compliant: {compliance['non_compliant_tools']}")
            
            if compliance['non_compliant_tools'] > 0:
                print("\n2. Enforcing compliance...")
                enforcement = automation.enforce_compliance_on_all_tools()
                print(f"   Enforced: {enforcement['enforced']}")
                print(f"   Failed: {enforcement['failed']}")
            
            print("\n3. Generating report...")
            report_path = automation.generate_compliance_report()
            print(f"   Report: {report_path}")
            
            print("\n✅ Guardian's Forge automation completed!")
    
    except Exception as e:
        print(f"❌ Automation failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())