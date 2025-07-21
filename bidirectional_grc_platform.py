#!/usr/bin/env python3
"""
Guardians Armory: Bidirectional GRC Platform
============================================

A comprehensive GRC platform that implements bidirectional accessibility:
- Every GUI feature has a CLI/API equivalent
- Every CLI/API feature has a GUI equivalent
- Seamless integration between all interfaces
- Consistent functionality across all access methods

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import json
import datetime
import argparse
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from flask import Flask, request, jsonify, render_template_string
import threading
import time

class ControlStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"

class DataSource(Enum):
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_CONFIG = "aws_config"
    AWS_SECURITY_HUB = "aws_security_hub"
    AWS_GUARDDUTY = "aws_guardduty"
    MANUAL_ASSESSMENT = "manual_assessment"
    API_SCAN = "api_scan"

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

class BidirectionalGRCPlatform:
    """Bidirectional GRC platform with CLI, API, and GUI"""
    
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
    
    # ==================== CORE OPERATIONS ====================
    
    def get_control_summary(self) -> Dict[str, Any]:
        """Get overall control summary - available via CLI, API, and GUI"""
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
        """Get detailed control information - available via CLI, API, and GUI"""
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
        """Run assessment on control(s) - available via CLI, API, and GUI"""
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
        """Generate reports - available via CLI, API, and GUI"""
        summary = self.get_control_summary()
        
        report = {
            "report_id": str(uuid.uuid4()),
            "report_type": report_type,
            "format": format,
            "timestamp": datetime.datetime.now().isoformat(),
            "summary": summary,
            "controls": [self.get_control_details(cid) for cid in self.controls.keys()],
            "assessments": self.assessments[-10:] if self.assessments else []  # Last 10 assessments
        }
        
        self.reports.append(report)
        return report
    
    def update_control(self, control_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update control information - available via CLI, API, and GUI"""
        control = self.controls.get(control_id)
        if not control:
            return {"error": f"Control {control_id} not found"}
        
        # Update allowed fields
        allowed_fields = ["name", "description", "owner", "priority", "next_assessment"]
        for field in allowed_fields:
            if field in updates:
                setattr(control, field, updates[field])
        
        return {"success": True, "control": self.get_control_details(control_id)}
    
    def add_control(self, control_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add new control - available via CLI, API, and GUI"""
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

class GRCCLI:
    """Command-line interface for GRC platform"""
    
    def __init__(self, platform: BidirectionalGRCPlatform):
        self.platform = platform
        self.parser = self._setup_parser()
    
    def _setup_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Guardians Armory GRC Platform CLI")
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Summary command
        summary_parser = subparsers.add_parser("summary", help="Get control summary")
        
        # Details command
        details_parser = subparsers.add_parser("details", help="Get control details")
        details_parser.add_argument("control_id", help="Control ID to get details for")
        
        # Assessment command
        assessment_parser = subparsers.add_parser("assess", help="Run assessment")
        assessment_parser.add_argument("--control-id", help="Specific control ID to assess")
        
        # Report command
        report_parser = subparsers.add_parser("report", help="Generate report")
        report_parser.add_argument("--type", default="compliance", help="Report type")
        report_parser.add_argument("--format", default="json", help="Report format")
        
        # Update command
        update_parser = subparsers.add_parser("update", help="Update control")
        update_parser.add_argument("control_id", help="Control ID to update")
        update_parser.add_argument("--name", help="New control name")
        update_parser.add_argument("--owner", help="New owner")
        update_parser.add_argument("--priority", help="New priority")
        
        # Add command
        add_parser = subparsers.add_parser("add", help="Add new control")
        add_parser.add_argument("--name", required=True, help="Control name")
        add_parser.add_argument("--description", help="Control description")
        add_parser.add_argument("--framework", default="SOC2", help="Compliance framework")
        add_parser.add_argument("--category", help="Control category")
        add_parser.add_argument("--owner", help="Control owner")
        
        return parser
    
    def run(self, args=None):
        """Run CLI with arguments"""
        parsed_args = self.parser.parse_args(args)
        
        if parsed_args.command == "summary":
            result = self.platform.get_control_summary()
            print(json.dumps(result, indent=2))
        
        elif parsed_args.command == "details":
            result = self.platform.get_control_details(parsed_args.control_id)
            if result:
                print(json.dumps(result, indent=2))
            else:
                print(f"Control {parsed_args.control_id} not found")
        
        elif parsed_args.command == "assess":
            result = self.platform.run_assessment(parsed_args.control_id)
            print(json.dumps(result, indent=2))
        
        elif parsed_args.command == "report":
            result = self.platform.generate_report(parsed_args.type, parsed_args.format)
            print(json.dumps(result, indent=2))
        
        elif parsed_args.command == "update":
            updates = {}
            if parsed_args.name:
                updates["name"] = parsed_args.name
            if parsed_args.owner:
                updates["owner"] = parsed_args.owner
            if parsed_args.priority:
                updates["priority"] = parsed_args.priority
            
            result = self.platform.update_control(parsed_args.control_id, updates)
            print(json.dumps(result, indent=2))
        
        elif parsed_args.command == "add":
            control_data = {
                "name": parsed_args.name,
                "description": parsed_args.description or "",
                "framework": parsed_args.framework,
                "category": parsed_args.category or "General",
                "owner": parsed_args.owner or "Security Team"
            }
            result = self.platform.add_control(control_data)
            print(json.dumps(result, indent=2))
        
        else:
            self.parser.print_help()

# ==================== API INTERFACE ====================

class GRCAPI:
    """REST API interface for GRC platform"""
    
    def __init__(self, platform: BidirectionalGRCPlatform):
        self.platform = platform
        self.app = Flask(__name__)
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/summary', methods=['GET'])
        def get_summary():
            """Get control summary - GUI equivalent: Dashboard overview"""
            return jsonify(self.platform.get_control_summary())
        
        @self.app.route('/api/controls', methods=['GET'])
        def get_controls():
            """Get all controls - GUI equivalent: Controls list view"""
            controls = [self.platform.get_control_details(cid) for cid in self.platform.controls.keys()]
            return jsonify({"controls": controls})
        
        @self.app.route('/api/controls/<control_id>', methods=['GET'])
        def get_control(control_id):
            """Get specific control - GUI equivalent: Control detail view"""
            result = self.platform.get_control_details(control_id)
            if result:
                return jsonify(result)
            return jsonify({"error": "Control not found"}), 404
        
        @self.app.route('/api/assess', methods=['POST'])
        def run_assessment():
            """Run assessment - GUI equivalent: Assessment button"""
            data = request.get_json() or {}
            control_id = data.get('control_id')
            result = self.platform.run_assessment(control_id)
            return jsonify(result)
        
        @self.app.route('/api/reports', methods=['POST'])
        def generate_report():
            """Generate report - GUI equivalent: Report generation form"""
            data = request.get_json() or {}
            report_type = data.get('type', 'compliance')
            format = data.get('format', 'json')
            result = self.platform.generate_report(report_type, format)
            return jsonify(result)
        
        @self.app.route('/api/controls/<control_id>', methods=['PUT'])
        def update_control(control_id):
            """Update control - GUI equivalent: Control edit form"""
            updates = request.get_json() or {}
            result = self.platform.update_control(control_id, updates)
            if "error" in result:
                return jsonify(result), 400
            return jsonify(result)
        
        @self.app.route('/api/controls', methods=['POST'])
        def add_control():
            """Add control - GUI equivalent: New control form"""
            control_data = request.get_json() or {}
            result = self.platform.add_control(control_data)
            if "error" in result:
                return jsonify(result), 400
            return jsonify(result), 201
        
        @self.app.route('/api/assessments', methods=['GET'])
        def get_assessments():
            """Get assessments - GUI equivalent: Assessment history"""
            return jsonify({"assessments": self.platform.assessments})
        
        @self.app.route('/api/reports', methods=['GET'])
        def get_reports():
            """Get reports - GUI equivalent: Report library"""
            return jsonify({"reports": self.platform.reports})
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run API server"""
        self.app.run(host=host, port=port, debug=debug)

# ==================== GUI INTERFACE ====================

class GRCGUI:
    """Web-based GUI interface for GRC platform"""
    
    def __init__(self, platform: BidirectionalGRCPlatform):
        self.platform = platform
        self.app = Flask(__name__)
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup GUI routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard - CLI equivalent: grc summary"""
            summary = self.platform.get_control_summary()
            controls = [self.platform.get_control_details(cid) for cid in self.platform.controls.keys()]
            return self._render_dashboard(summary, controls)
        
        @self.app.route('/control/<control_id>')
        def control_detail(control_id):
            """Control detail view - CLI equivalent: grc details <control_id>"""
            control = self.platform.get_control_details(control_id)
            if not control:
                return "Control not found", 404
            return self._render_control_detail(control)
        
        @self.app.route('/assess', methods=['GET', 'POST'])
        def assessment():
            """Assessment interface - CLI equivalent: grc assess"""
            if request.method == 'POST':
                control_id = request.form.get('control_id')
                result = self.platform.run_assessment(control_id)
                return self._render_assessment_result(result)
            return self._render_assessment_form()
        
        @self.app.route('/reports', methods=['GET', 'POST'])
        def reports():
            """Report generation - CLI equivalent: grc report"""
            if request.method == 'POST':
                report_type = request.form.get('type', 'compliance')
                format = request.form.get('format', 'json')
                result = self.platform.generate_report(report_type, format)
                return self._render_report_result(result)
            return self._render_report_form()
        
        @self.app.route('/control/<control_id>/edit', methods=['GET', 'POST'])
        def edit_control(control_id):
            """Edit control - CLI equivalent: grc update <control_id>"""
            if request.method == 'POST':
                updates = {
                    'name': request.form.get('name'),
                    'owner': request.form.get('owner'),
                    'priority': request.form.get('priority')
                }
                result = self.platform.update_control(control_id, updates)
                return self._render_control_detail(result['control'])
            
            control = self.platform.get_control_details(control_id)
            if not control:
                return "Control not found", 404
            return self._render_edit_control(control)
        
        @self.app.route('/control/add', methods=['GET', 'POST'])
        def add_control():
            """Add control - CLI equivalent: grc add"""
            if request.method == 'POST':
                control_data = {
                    'name': request.form.get('name'),
                    'description': request.form.get('description'),
                    'framework': request.form.get('framework'),
                    'category': request.form.get('category'),
                    'owner': request.form.get('owner')
                }
                result = self.platform.add_control(control_data)
                return self._render_control_detail(result['control'])
            return self._render_add_control()
    
    def _render_dashboard(self, summary, controls):
        """Render main dashboard"""
        return f"""
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
            </style>
        </head>
        <body>
            <div class="nav">
                <h1>🛡️ Guardians Armory GRC Platform</h1>
                <a href="/assess">Run Assessment</a> |
                <a href="/reports">Generate Reports</a> |
                <a href="/control/add">Add Control</a>
            </div>
            
            <h2>Compliance Summary</h2>
            <div class="metric">
                <strong>Overall Compliance:</strong> {summary['compliance_score']}%
            </div>
            <div class="metric">
                <strong>Total Controls:</strong> {summary['total_controls']}
            </div>
            <div class="metric">
                <strong>Passed:</strong> {summary['passed_controls']}
            </div>
            <div class="metric">
                <strong>Warnings:</strong> {summary['warning_controls']}
            </div>
            <div class="metric">
                <strong>Failed:</strong> {summary['failed_controls']}
            </div>
            
            <h2>Controls</h2>
            {''.join([f'''
            <div class="control">
                <h3><a href="/control/{c['control_id']}">{c['name']}</a></h3>
                <p>Status: <span class="status-{c['status']}">{c['status'].upper()}</span></p>
                <p>Framework: {c['framework']} | Category: {c['category']}</p>
                <p>Owner: {c['owner']} | Priority: {c['priority']}</p>
            </div>
            ''' for c in controls])}
        </body>
        </html>
        """
    
    def _render_control_detail(self, control):
        """Render control detail view"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{control['name']} - Guardians Armory</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }}
                .detail {{ background: #1a1a1a; padding: 20px; margin: 10px; border-radius: 8px; }}
                .parameter {{ background: #0f0f0f; padding: 10px; margin: 5px; border-radius: 4px; }}
                .status-passed {{ color: #00d4aa; }}
                .status-warning {{ color: #ffa500; }}
                .status-failed {{ color: #ff4757; }}
                a {{ color: #00d4aa; text-decoration: none; }}
            </style>
        </head>
        <body>
            <h1><a href="/">← Back to Dashboard</a></h1>
            <h2>{control['name']}</h2>
            
            <div class="detail">
                <h3>Control Information</h3>
                <p><strong>ID:</strong> {control['control_id']}</p>
                <p><strong>Description:</strong> {control['description']}</p>
                <p><strong>Framework:</strong> {control['framework']}</p>
                <p><strong>Category:</strong> {control['category']}</p>
                <p><strong>Status:</strong> <span class="status-{control['status']}">{control['status'].upper()}</span></p>
                <p><strong>Owner:</strong> {control['owner']}</p>
                <p><strong>Priority:</strong> {control['priority']}</p>
                <p><strong>Automated:</strong> {control['automated']}</p>
                <p><strong>Last Assessment:</strong> {control['last_assessment']}</p>
                <p><strong>Next Assessment:</strong> {control['next_assessment']}</p>
                
                <h3>Parameters</h3>
                {''.join([f'''
                <div class="parameter">
                    <strong>{p['name']}</strong><br>
                    Status: <span class="status-{p['status']}">{p['status'].upper()}</span><br>
                    Data Source: {p['data_source']}<br>
                    Evidence: {p['evidence']}<br>
                    Last Checked: {p['last_checked']}
                </div>
                ''' for p in control['parameters']])}
            </div>
            
            <p><a href="/control/{control['control_id']}/edit">Edit Control</a></p>
        </body>
        </html>
        """
    
    def _render_assessment_form(self):
        """Render assessment form"""
        controls = [self.platform.get_control_details(cid) for cid in self.platform.controls.keys()]
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Run Assessment - Guardians Armory</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }}
                .form {{ background: #1a1a1a; padding: 20px; border-radius: 8px; }}
                select, button {{ padding: 10px; margin: 10px; background: #2a2a2a; color: #ffffff; border: 1px solid #00d4aa; }}
                a {{ color: #00d4aa; text-decoration: none; }}
            </style>
        </head>
        <body>
            <h1><a href="/">← Back to Dashboard</a></h1>
            <h2>Run Assessment</h2>
            
            <div class="form">
                <form method="POST">
                    <label>Select Control (leave empty for full assessment):</label><br>
                    <select name="control_id">
                        <option value="">All Controls</option>
                        {''.join([f'<option value="{c["control_id"]}">{c["name"]}</option>' for c in controls])}
                    </select><br>
                    <button type="submit">Run Assessment</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def _render_assessment_result(self, result):
        """Render assessment result"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Assessment Result - Guardians Armory</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }}
                .result {{ background: #1a1a1a; padding: 20px; border-radius: 8px; }}
                .finding {{ background: #0f0f0f; padding: 10px; margin: 5px; border-radius: 4px; }}
                a {{ color: #00d4aa; text-decoration: none; }}
            </style>
        </head>
        <body>
            <h1><a href="/">← Back to Dashboard</a></h1>
            <h2>Assessment Result</h2>
            
            <div class="result">
                <p><strong>Assessment ID:</strong> {result['assessment_id']}</p>
                <p><strong>Status:</strong> {result['status']}</p>
                <p><strong>Timestamp:</strong> {result['timestamp']}</p>
                
                {f'<p><strong>Control Assessed:</strong> {result["control_id"]}</p>' if 'control_id' in result else ''}
                {f'<p><strong>Controls Assessed:</strong> {result["controls_assessed"]}</p>' if 'controls_assessed' in result else ''}
                
                <h3>Findings</h3>
                {''.join([f'''
                <div class="finding">
                    <strong>{f['parameter']}</strong><br>
                    Status: {f['status']}<br>
                    Evidence: {f['evidence']}<br>
                    Remediation: {f['remediation']}
                </div>
                ''' for f in result.get('findings', [])])}
            </div>
        </body>
        </html>
        """
    
    def _render_report_form(self):
        """Render report form"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Generate Report - Guardians Armory</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }
                .form { background: #1a1a1a; padding: 20px; border-radius: 8px; }
                select, button { padding: 10px; margin: 10px; background: #2a2a2a; color: #ffffff; border: 1px solid #00d4aa; }
                a { color: #00d4aa; text-decoration: none; }
            </style>
        </head>
        <body>
            <h1><a href="/">← Back to Dashboard</a></h1>
            <h2>Generate Report</h2>
            
            <div class="form">
                <form method="POST">
                    <label>Report Type:</label><br>
                    <select name="type">
                        <option value="compliance">Compliance Report</option>
                        <option value="security">Security Report</option>
                        <option value="audit">Audit Report</option>
                    </select><br>
                    
                    <label>Format:</label><br>
                    <select name="format">
                        <option value="json">JSON</option>
                        <option value="html">HTML</option>
                        <option value="pdf">PDF</option>
                    </select><br>
                    
                    <button type="submit">Generate Report</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def _render_report_result(self, result):
        """Render report result"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Report Generated - Guardians Armory</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }}
                .result {{ background: #1a1a1a; padding: 20px; border-radius: 8px; }}
                .data {{ background: #0f0f0f; padding: 10px; margin: 5px; border-radius: 4px; font-family: monospace; }}
                a {{ color: #00d4aa; text-decoration: none; }}
            </style>
        </head>
        <body>
            <h1><a href="/">← Back to Dashboard</a></h1>
            <h2>Report Generated</h2>
            
            <div class="result">
                <p><strong>Report ID:</strong> {result['report_id']}</p>
                <p><strong>Type:</strong> {result['report_type']}</p>
                <p><strong>Format:</strong> {result['format']}</p>
                <p><strong>Timestamp:</strong> {result['timestamp']}</p>
                
                <h3>Summary</h3>
                <div class="data">
                    {json.dumps(result['summary'], indent=2)}
                </div>
                
                <h3>Controls ({len(result['controls'])} total)</h3>
                {''.join([f'<p>• {c["name"]} ({c["status"]})</p>' for c in result['controls']])}
            </div>
        </body>
        </html>
        """
    
    def _render_edit_control(self, control):
        """Render edit control form"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Edit {control['name']} - Guardians Armory</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }}
                .form {{ background: #1a1a1a; padding: 20px; border-radius: 8px; }}
                input, select, button {{ padding: 10px; margin: 10px; background: #2a2a2a; color: #ffffff; border: 1px solid #00d4aa; }}
                a {{ color: #00d4aa; text-decoration: none; }}
            </style>
        </head>
        <body>
            <h1><a href="/control/{control['control_id']}">← Back to Control</a></h1>
            <h2>Edit {control['name']}</h2>
            
            <div class="form">
                <form method="POST">
                    <label>Name:</label><br>
                    <input type="text" name="name" value="{control['name']}"><br>
                    
                    <label>Owner:</label><br>
                    <input type="text" name="owner" value="{control['owner']}"><br>
                    
                    <label>Priority:</label><br>
                    <select name="priority">
                        <option value="Critical" {'selected' if control['priority'] == 'Critical' else ''}>Critical</option>
                        <option value="High" {'selected' if control['priority'] == 'High' else ''}>High</option>
                        <option value="Medium" {'selected' if control['priority'] == 'Medium' else ''}>Medium</option>
                        <option value="Low" {'selected' if control['priority'] == 'Low' else ''}>Low</option>
                    </select><br>
                    
                    <button type="submit">Update Control</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def _render_add_control(self):
        """Render add control form"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Add Control - Guardians Armory</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #0a0a0a; color: #ffffff; }
                .form { background: #1a1a1a; padding: 20px; border-radius: 8px; }
                input, select, textarea, button { padding: 10px; margin: 10px; background: #2a2a2a; color: #ffffff; border: 1px solid #00d4aa; }
                a { color: #00d4aa; text-decoration: none; }
            </style>
        </head>
        <body>
            <h1><a href="/">← Back to Dashboard</a></h1>
            <h2>Add New Control</h2>
            
            <div class="form">
                <form method="POST">
                    <label>Name:</label><br>
                    <input type="text" name="name" required><br>
                    
                    <label>Description:</label><br>
                    <textarea name="description" rows="3"></textarea><br>
                    
                    <label>Framework:</label><br>
                    <select name="framework">
                        <option value="SOC2">SOC2</option>
                        <option value="ISO27001">ISO27001</option>
                        <option value="NIST">NIST</option>
                        <option value="PCI-DSS">PCI-DSS</option>
                    </select><br>
                    
                    <label>Category:</label><br>
                    <input type="text" name="category"><br>
                    
                    <label>Owner:</label><br>
                    <input type="text" name="owner"><br>
                    
                    <button type="submit">Add Control</button>
                </form>
            </div>
        </body>
        </html>
        """
    
    def run(self, host='0.0.0.0', port=8080, debug=False):
        """Run GUI server"""
        self.app.run(host=host, port=port, debug=debug)

# ==================== MAIN APPLICATION ====================

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="Guardians Armory Bidirectional GRC Platform")
    parser.add_argument("--interface", choices=["cli", "api", "gui"], default="cli", 
                       help="Interface to use (cli, api, gui)")
    parser.add_argument("--host", default="0.0.0.0", help="Host for API/GUI server")
    parser.add_argument("--port", type=int, default=5000, help="Port for API/GUI server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    # Parse CLI arguments if using CLI interface
    if len(sys.argv) > 1 and sys.argv[1] not in ["--interface", "--host", "--port", "--debug"]:
        # CLI mode with specific command
        platform = BidirectionalGRCPlatform()
        cli = GRCCLI(platform)
        cli.run()
        return
    
    args = parser.parse_args()
    
    # Initialize platform
    platform = BidirectionalGRCPlatform()
    
    if args.interface == "cli":
        print("Guardians Armory GRC Platform - CLI Mode")
        print("Available commands:")
        print("  grc summary                    - Get control summary")
        print("  grc details <control_id>       - Get control details")
        print("  grc assess [--control-id ID]   - Run assessment")
        print("  grc report [--type TYPE]       - Generate report")
        print("  grc update <control_id>        - Update control")
        print("  grc add --name NAME            - Add new control")
        print("\nExamples:")
        print("  python bidirectional_grc_platform.py summary")
        print("  python bidirectional_grc_platform.py details CC6.1")
        print("  python bidirectional_grc_platform.py assess --control-id CC6.1")
        
        cli = GRCCLI(platform)
        cli.run()
    
    elif args.interface == "api":
        print(f"Starting GRC API server on {args.host}:{args.port}")
        api = GRCAPI(platform)
        api.run(host=args.host, port=args.port, debug=args.debug)
    
    elif args.interface == "gui":
        print(f"Starting GRC GUI server on {args.host}:{args.port}")
        gui = GRCGUI(platform)
        gui.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()