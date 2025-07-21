#!/usr/bin/env python3
"""
Guardians Armory: Simple Bidirectional GRC Platform
==================================================

A simplified demonstration of bidirectional accessibility:
- Every CLI feature has a GUI equivalent
- Every GUI feature has a CLI equivalent
- Shared core platform with consistent functionality

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import json
import datetime
import argparse
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import uuid

class ControlStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"

@dataclass
class SecurityControl:
    """Security control with comprehensive details"""
    control_id: str
    name: str
    description: str
    framework: str
    category: str
    status: ControlStatus
    parameters: List[Dict[str, Any]]
    last_assessment: datetime.datetime
    next_assessment: datetime.datetime
    owner: str
    priority: str
    automated: bool
    evidence_summary: str

class SimpleBidirectionalGRC:
    """Simple bidirectional GRC platform demonstrating the principle"""
    
    def __init__(self):
        self.controls: Dict[str, SecurityControl] = {}
        self.assessments: List[Dict[str, Any]] = []
        self.reports: List[Dict[str, Any]] = []
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize sample controls and data"""
        
        # Sample controls
        self.controls["CC6.1"] = SecurityControl(
            control_id="CC6.1",
            name="Access Control",
            description="Logical access security controls",
            framework="SOC2",
            category="Access Control",
            status=ControlStatus.WARNING,
            parameters=[
                {
                    "name": "MFA Enforcement",
                    "status": "warning",
                    "data_source": "AWS Security Hub",
                    "evidence": "2 users without MFA",
                    "last_checked": datetime.datetime.now().isoformat()
                }
            ],
            last_assessment=datetime.datetime.now() - datetime.timedelta(hours=2),
            next_assessment=datetime.datetime.now() + datetime.timedelta(days=7),
            owner="Security Team",
            priority="Critical",
            automated=True,
            evidence_summary="2/3 parameters passed"
        )
        
        self.controls["CC6.7"] = SecurityControl(
            control_id="CC6.7",
            name="Data Protection",
            description="Data encryption and protection controls",
            framework="SOC2",
            category="Data Protection",
            status=ControlStatus.PASSED,
            parameters=[
                {
                    "name": "S3 Encryption",
                    "status": "passed",
                    "data_source": "AWS S3",
                    "evidence": "All buckets encrypted",
                    "last_checked": datetime.datetime.now().isoformat()
                }
            ],
            last_assessment=datetime.datetime.now() - datetime.timedelta(hours=3),
            next_assessment=datetime.datetime.now() + datetime.timedelta(days=14),
            owner="Infrastructure Team",
            priority="Critical",
            automated=True,
            evidence_summary="1/1 parameters passed"
        )
    
    # ==================== CORE OPERATIONS (Shared by CLI and GUI) ====================
    
    def get_control_summary(self) -> Dict[str, Any]:
        """Get overall control summary - available via CLI and GUI"""
        total_controls = len(self.controls)
        passed_controls = sum(1 for c in self.controls.values() if c.status == ControlStatus.PASSED)
        failed_controls = sum(1 for c in self.controls.values() if c.status == ControlStatus.FAILED)
        warning_controls = sum(1 for c in self.controls.values() if c.status == ControlStatus.WARNING)
        
        return {
            "total_controls": total_controls,
            "passed_controls": passed_controls,
            "failed_controls": failed_controls,
            "warning_controls": warning_controls,
            "compliance_score": round((passed_controls / total_controls) * 100, 1) if total_controls > 0 else 0,
            "last_updated": datetime.datetime.now().isoformat()
        }
    
    def get_control_details(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed control information - available via CLI and GUI"""
        control = self.controls.get(control_id)
        if not control:
            return None
        
        return {
            "control_id": control.control_id,
            "name": control.name,
            "description": control.description,
            "framework": control.framework,
            "category": control.category,
            "status": control.status.value,
            "parameters": control.parameters,
            "last_assessment": control.last_assessment.isoformat(),
            "next_assessment": control.next_assessment.isoformat(),
            "owner": control.owner,
            "priority": control.priority,
            "automated": control.automated,
            "evidence_summary": control.evidence_summary
        }
    
    def run_assessment(self, control_id: Optional[str] = None) -> Dict[str, Any]:
        """Run assessment on control(s) - available via CLI and GUI"""
        if control_id:
            # Single control assessment
            control = self.controls.get(control_id)
            if not control:
                return {"error": f"Control {control_id} not found"}
            
            # Simulate assessment
            assessment_result = {
                "assessment_id": str(uuid.uuid4()),
                "control_id": control_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "status": "completed",
                "findings": [
                    {
                        "parameter": "MFA Enforcement",
                        "status": "warning",
                        "evidence": "2 users without MFA devices",
                        "remediation": "Enable MFA for remaining users"
                    }
                ]
            }
            
            self.assessments.append(assessment_result)
            return assessment_result
        else:
            # Full assessment
            results = []
            for control in self.controls.values():
                result = self.run_assessment(control.control_id)
                results.append(result)
            
            return {
                "assessment_id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.now().isoformat(),
                "status": "completed",
                "controls_assessed": len(results),
                "results": results
            }
    
    def generate_report(self, report_type: str = "compliance", format: str = "json") -> Dict[str, Any]:
        """Generate reports - available via CLI and GUI"""
        summary = self.get_control_summary()
        
        report = {
            "report_id": str(uuid.uuid4()),
            "report_type": report_type,
            "format": format,
            "timestamp": datetime.datetime.now().isoformat(),
            "summary": summary,
            "controls": [self.get_control_details(cid) for cid in self.controls.keys()],
            "assessments": self.assessments[-10:] if self.assessments else []
        }
        
        self.reports.append(report)
        return report
    
    def update_control(self, control_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update control information - available via CLI and GUI"""
        control = self.controls.get(control_id)
        if not control:
            return {"error": f"Control {control_id} not found"}
        
        # Update allowed fields
        allowed_fields = ["name", "description", "owner", "priority"]
        for field in allowed_fields:
            if field in updates:
                setattr(control, field, updates[field])
        
        return {"success": True, "control": self.get_control_details(control_id)}
    
    def add_control(self, control_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add new control - available via CLI and GUI"""
        control_id = control_data.get("control_id")
        if not control_id:
            control_id = f"CC{len(self.controls) + 1}.{len(self.controls) + 1}"
        
        if control_id in self.controls:
            return {"error": f"Control {control_id} already exists"}
        
        new_control = SecurityControl(
            control_id=control_id,
            name=control_data.get("name", "New Control"),
            description=control_data.get("description", ""),
            framework=control_data.get("framework", "SOC2"),
            category=control_data.get("category", "General"),
            status=ControlStatus(control_data.get("status", "not_applicable")),
            parameters=control_data.get("parameters", []),
            last_assessment=datetime.datetime.now(),
            next_assessment=datetime.datetime.now() + datetime.timedelta(days=30),
            owner=control_data.get("owner", "Security Team"),
            priority=control_data.get("priority", "Medium"),
            automated=control_data.get("automated", False),
            evidence_summary=control_data.get("evidence_summary", "No evidence yet")
        )
        
        self.controls[control_id] = new_control
        return {"success": True, "control": self.get_control_details(control_id)}

# ==================== CLI INTERFACE ====================

class SimpleGRCCLI:
    """Command-line interface for GRC platform"""
    
    def __init__(self, platform: SimpleBidirectionalGRC):
        self.platform = platform
        self.parser = self._setup_parser()
    
    def _setup_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Guardians Armory Simple GRC Platform CLI")
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Summary command
        summary_parser = subparsers.add_parser("summary", help="Get control summary (GUI equivalent: Dashboard)")
        
        # Details command
        details_parser = subparsers.add_parser("details", help="Get control details (GUI equivalent: Control detail page)")
        details_parser.add_argument("control_id", help="Control ID to get details for")
        
        # Assessment command
        assessment_parser = subparsers.add_parser("assess", help="Run assessment (GUI equivalent: Assessment button)")
        assessment_parser.add_argument("--control-id", help="Specific control ID to assess")
        
        # Report command
        report_parser = subparsers.add_parser("report", help="Generate report (GUI equivalent: Report form)")
        report_parser.add_argument("--type", default="compliance", help="Report type")
        report_parser.add_argument("--format", default="json", help="Report format")
        
        # Update command
        update_parser = subparsers.add_parser("update", help="Update control (GUI equivalent: Edit form)")
        update_parser.add_argument("control_id", help="Control ID to update")
        update_parser.add_argument("--name", help="New control name")
        update_parser.add_argument("--owner", help="New owner")
        update_parser.add_argument("--priority", help="New priority")
        
        # Add command
        add_parser = subparsers.add_parser("add", help="Add new control (GUI equivalent: New control form)")
        add_parser.add_argument("--name", required=True, help="Control name")
        add_parser.add_argument("--description", help="Control description")
        add_parser.add_argument("--framework", default="SOC2", help="Compliance framework")
        add_parser.add_argument("--category", help="Control category")
        add_parser.add_argument("--owner", help="Control owner")
        
        # List command
        list_parser = subparsers.add_parser("list", help="List all controls (GUI equivalent: Controls list)")
        
        return parser
    
    def run(self, args=None):
        """Run CLI with arguments"""
        parsed_args = self.parser.parse_args(args)
        
        if parsed_args.command == "summary":
            result = self.platform.get_control_summary()
            print("🛡️ Guardians Armory GRC Platform - Control Summary")
            print("=" * 50)
            print(f"Total Controls: {result['total_controls']}")
            print(f"Passed: {result['passed_controls']} 🟢")
            print(f"Warnings: {result['warning_controls']} 🟡")
            print(f"Failed: {result['failed_controls']} 🔴")
            print(f"Compliance Score: {result['compliance_score']}%")
            print(f"Last Updated: {result['last_updated']}")
            print("\n💡 GUI Equivalent: Dashboard overview page")
        
        elif parsed_args.command == "list":
            print("🛡️ Guardians Armory GRC Platform - Controls List")
            print("=" * 50)
            for control_id in self.platform.controls.keys():
                control = self.platform.get_control_details(control_id)
                status_emoji = "🟢" if control['status'] == 'passed' else "🟡" if control['status'] == 'warning' else "🔴"
                print(f"{control_id}: {control['name']} {status_emoji}")
                print(f"  Framework: {control['framework']} | Category: {control['category']}")
                print(f"  Owner: {control['owner']} | Priority: {control['priority']}")
                print()
            print("💡 GUI Equivalent: Controls list view")
        
        elif parsed_args.command == "details":
            result = self.platform.get_control_details(parsed_args.control_id)
            if result:
                print(f"🛡️ Guardians Armory GRC Platform - Control Details")
                print("=" * 50)
                print(f"Control ID: {result['control_id']}")
                print(f"Name: {result['name']}")
                print(f"Description: {result['description']}")
                print(f"Framework: {result['framework']}")
                print(f"Category: {result['category']}")
                print(f"Status: {result['status'].upper()}")
                print(f"Owner: {result['owner']}")
                print(f"Priority: {result['priority']}")
                print(f"Automated: {result['automated']}")
                print(f"Last Assessment: {result['last_assessment']}")
                print(f"Next Assessment: {result['next_assessment']}")
                print(f"Evidence Summary: {result['evidence_summary']}")
                
                print("\nParameters:")
                for param in result['parameters']:
                    status_emoji = "🟢" if param['status'] == 'passed' else "🟡" if param['status'] == 'warning' else "🔴"
                    print(f"  • {param['name']} {status_emoji}")
                    print(f"    Data Source: {param['data_source']}")
                    print(f"    Evidence: {param['evidence']}")
                    print(f"    Last Checked: {param['last_checked']}")
                    print()
                
                print("💡 GUI Equivalent: Control detail page")
            else:
                print(f"❌ Control {parsed_args.control_id} not found")
        
        elif parsed_args.command == "assess":
            result = self.platform.run_assessment(parsed_args.control_id)
            print("🛡️ Guardians Armory GRC Platform - Assessment Result")
            print("=" * 50)
            print(f"Assessment ID: {result['assessment_id']}")
            print(f"Status: {result['status']}")
            print(f"Timestamp: {result['timestamp']}")
            
            if 'control_id' in result:
                print(f"Control Assessed: {result['control_id']}")
            if 'controls_assessed' in result:
                print(f"Controls Assessed: {result['controls_assessed']}")
            
            if 'findings' in result:
                print("\nFindings:")
                for finding in result['findings']:
                    status_emoji = "🟢" if finding['status'] == 'passed' else "🟡" if finding['status'] == 'warning' else "🔴"
                    print(f"  • {finding['parameter']} {status_emoji}")
                    print(f"    Evidence: {finding['evidence']}")
                    print(f"    Remediation: {finding['remediation']}")
                    print()
            
            print("💡 GUI Equivalent: Assessment button and results page")
        
        elif parsed_args.command == "report":
            result = self.platform.generate_report(parsed_args.type, parsed_args.format)
            print("🛡️ Guardians Armory GRC Platform - Report Generated")
            print("=" * 50)
            print(f"Report ID: {result['report_id']}")
            print(f"Type: {result['report_type']}")
            print(f"Format: {result['format']}")
            print(f"Timestamp: {result['timestamp']}")
            print(f"Controls Included: {len(result['controls'])}")
            print(f"Assessments Included: {len(result['assessments'])}")
            print("\nSummary:")
            summary = result['summary']
            print(f"  Compliance Score: {summary['compliance_score']}%")
            print(f"  Total Controls: {summary['total_controls']}")
            print(f"  Passed: {summary['passed_controls']}")
            print(f"  Warnings: {summary['warning_controls']}")
            print(f"  Failed: {summary['failed_controls']}")
            print("\n💡 GUI Equivalent: Report generation form and results")
        
        elif parsed_args.command == "update":
            updates = {}
            if parsed_args.name:
                updates["name"] = parsed_args.name
            if parsed_args.owner:
                updates["owner"] = parsed_args.owner
            if parsed_args.priority:
                updates["priority"] = parsed_args.priority
            
            result = self.platform.update_control(parsed_args.control_id, updates)
            if "error" in result:
                print(f"❌ {result['error']}")
            else:
                print("✅ Control updated successfully")
                control = result['control']
                print(f"Control ID: {control['control_id']}")
                print(f"Name: {control['name']}")
                print(f"Owner: {control['owner']}")
                print(f"Priority: {control['priority']}")
                print("\n💡 GUI Equivalent: Control edit form")
        
        elif parsed_args.command == "add":
            control_data = {
                "name": parsed_args.name,
                "description": parsed_args.description or "",
                "framework": parsed_args.framework,
                "category": parsed_args.category or "General",
                "owner": parsed_args.owner or "Security Team"
            }
            result = self.platform.add_control(control_data)
            if "error" in result:
                print(f"❌ {result['error']}")
            else:
                print("✅ Control added successfully")
                control = result['control']
                print(f"Control ID: {control['control_id']}")
                print(f"Name: {control['name']}")
                print(f"Framework: {control['framework']}")
                print(f"Category: {control['category']}")
                print(f"Owner: {control['owner']}")
                print("\n💡 GUI Equivalent: New control form")
        
        else:
            self.parser.print_help()

# ==================== GUI INTERFACE (HTML Generation) ====================

class SimpleGRCGUI:
    """Simple HTML GUI interface for GRC platform"""
    
    def __init__(self, platform: SimpleBidirectionalGRC):
        self.platform = platform
    
    def generate_dashboard_html(self) -> str:
        """Generate dashboard HTML - CLI equivalent: grc summary"""
        summary = self.platform.get_control_summary()
        controls = [self.platform.get_control_details(cid) for cid in self.platform.controls.keys()]
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Guardians Armory - GRC Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }}
        .metric {{ background: #1a1a1a; padding: 20px; margin: 10px; border-radius: 8px; display: inline-block; }}
        .control {{ background: #1a1a1a; padding: 15px; margin: 10px; border-radius: 8px; }}
        .status-passed {{ color: #00d4aa; }}
        .status-warning {{ color: #ffa500; }}
        .status-failed {{ color: #ff4757; }}
        a {{ color: #00d4aa; text-decoration: none; }}
        .nav {{ margin-bottom: 20px; }}
        .cli-note {{ background: #2a2a2a; padding: 10px; margin: 10px; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="nav">
        <h1>🛡️ Guardians Armory GRC Platform</h1>
        <p><strong>Bidirectional Accessibility Demo</strong> - Every GUI feature has a CLI equivalent</p>
    </div>
    
    <h2>Compliance Summary</h2>
    <div class="metric">
        <strong>Overall Compliance:</strong> {summary['compliance_score']}%
    </div>
    <div class="metric">
        <strong>Total Controls:</strong> {summary['total_controls']}
    </div>
    <div class="metric">
        <strong>Passed:</strong> {summary['passed_controls']} 🟢
    </div>
    <div class="metric">
        <strong>Warnings:</strong> {summary['warning_controls']} 🟡
    </div>
    <div class="metric">
        <strong>Failed:</strong> {summary['failed_controls']} 🔴
    </div>
    
    <div class="cli-note">
        💻 CLI Equivalent: <code>python simple_bidirectional_grc.py summary</code>
    </div>
    
    <h2>Controls</h2>
    {''.join([f'''
    <div class="control">
        <h3>{c['name']} ({c['control_id']})</h3>
        <p>Status: <span class="status-{c['status']}">{c['status'].upper()}</span></p>
        <p>Framework: {c['framework']} | Category: {c['category']}</p>
        <p>Owner: {c['owner']} | Priority: {c['priority']}</p>
        <p>💻 CLI Equivalent: <code>python simple_bidirectional_grc.py details {c['control_id']}</code></p>
    </div>
    ''' for c in controls])}
    
    <h2>Available Actions</h2>
    <div class="control">
        <h3>Run Assessment</h3>
        <p>💻 CLI Equivalent: <code>python simple_bidirectional_grc.py assess</code></p>
        <p>💻 CLI Equivalent (specific control): <code>python simple_bidirectional_grc.py assess --control-id CC6.1</code></p>
    </div>
    
    <div class="control">
        <h3>Generate Report</h3>
        <p>💻 CLI Equivalent: <code>python simple_bidirectional_grc.py report --type compliance</code></p>
    </div>
    
    <div class="control">
        <h3>Add New Control</h3>
        <p>💻 CLI Equivalent: <code>python simple_bidirectional_grc.py add --name "New Control" --framework SOC2</code></p>
    </div>
    
    <div class="control">
        <h3>Update Control</h3>
        <p>💻 CLI Equivalent: <code>python simple_bidirectional_grc.py update CC6.1 --name "Updated Name"</code></p>
    </div>
    
    <h2>Bidirectional Accessibility Principle</h2>
    <div class="control">
        <p><strong>"If the tools have a CLI or API, then we need to have a GUI for that. If you can do it in the GUI, then we need an API or CLI and vice versa."</strong></p>
        <p>✅ Every CLI command has a GUI equivalent</p>
        <p>✅ Every GUI action has a CLI equivalent</p>
        <p>✅ Shared core platform ensures consistency</p>
        <p>✅ Same data and functionality across interfaces</p>
    </div>
</body>
</html>
"""
        return html

# ==================== MAIN APPLICATION ====================

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="Guardians Armory Simple Bidirectional GRC Platform")
    parser.add_argument("--interface", choices=["cli", "gui"], default="cli", 
                       help="Interface to use (cli, gui)")
    parser.add_argument("--output", help="Output file for GUI HTML")
    
    # Parse CLI arguments if using CLI interface
    if len(sys.argv) > 1 and sys.argv[1] not in ["--interface", "--output"]:
        # CLI mode with specific command
        platform = SimpleBidirectionalGRC()
        cli = SimpleGRCCLI(platform)
        cli.run()
        return
    
    args = parser.parse_args()
    
    # Initialize platform
    platform = SimpleBidirectionalGRC()
    
    if args.interface == "cli":
        print("🛡️ Guardians Armory Simple GRC Platform - CLI Mode")
        print("=" * 60)
        print("Available commands:")
        print("  summary                    - Get control summary (GUI: Dashboard)")
        print("  list                       - List all controls (GUI: Controls list)")
        print("  details <control_id>       - Get control details (GUI: Control detail page)")
        print("  assess [--control-id ID]   - Run assessment (GUI: Assessment button)")
        print("  report [--type TYPE]       - Generate report (GUI: Report form)")
        print("  update <control_id>        - Update control (GUI: Edit form)")
        print("  add --name NAME            - Add new control (GUI: New control form)")
        print("\nExamples:")
        print("  python simple_bidirectional_grc.py summary")
        print("  python simple_bidirectional_grc.py details CC6.1")
        print("  python simple_bidirectional_grc.py assess --control-id CC6.1")
        print("  python simple_bidirectional_grc.py add --name 'Vulnerability Management'")
        print("\n💡 Every CLI command has a GUI equivalent!")
        
        cli = SimpleGRCCLI(platform)
        cli.run()
    
    elif args.interface == "gui":
        print("🛡️ Generating GUI HTML...")
        gui = SimpleGRCGUI(platform)
        html_content = gui.generate_dashboard_html()
        
        output_file = args.output or "simple_grc_gui.html"
        with open(output_file, "w") as f:
            f.write(html_content)
        
        print(f"✅ GUI HTML generated: {output_file}")
        print("🌐 Open the HTML file in your browser to view the GUI")
        print("💡 Every GUI action has a CLI equivalent!")

if __name__ == "__main__":
    main()