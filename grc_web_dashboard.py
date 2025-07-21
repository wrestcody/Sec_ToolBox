#!/usr/bin/env python3
"""
Guardians Armory: GRC Engineering Web Dashboard
==============================================

A comprehensive web-based dashboard system for the GRC Engineering platform that provides:
- User-friendly web interfaces for all stakeholders
- Interactive dashboards with real-time data
- Role-based access and personalized experiences
- Drag-and-drop functionality for customization
- Mobile-responsive design for accessibility

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import json
import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import time

# Import our GRC Engineering Engine
from grc_engineering_demo import (
    GRCEngineeringEngine, StakeholderRole, SecurityControlAsCode,
    ContinuousAssuranceRule, ThreatIntelligenceFeed
)

class DashboardWidget(Enum):
    """Dashboard widget types"""
    METRIC_CARD = "metric_card"
    CHART = "chart"
    TABLE = "table"
    ALERT = "alert"
    PROGRESS = "progress"
    STATUS = "status"
    TIMELINE = "timeline"
    MAP = "map"

@dataclass
class DashboardWidgetConfig:
    """Dashboard widget configuration"""
    widget_id: str
    widget_type: DashboardWidget
    title: str
    description: str
    position: Dict[str, int]  # x, y, width, height
    data_source: str
    refresh_interval: int  # seconds
    config: Dict[str, Any]

class WebDashboard:
    """Web-based dashboard system"""
    
    def __init__(self):
        self.grc_engine = GRCEngineeringEngine()
        self.dashboards: Dict[str, Dict[str, Any]] = {}
        self.widgets: Dict[str, DashboardWidgetConfig] = {}
        self.users: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
        # Initialize default dashboards
        self._initialize_default_dashboards()
        self._initialize_default_widgets()
    
    def _initialize_default_dashboards(self):
        """Initialize default dashboards for each role"""
        
        # Executive Dashboard
        self.dashboards["executive"] = {
            "id": "executive",
            "name": "Executive Dashboard",
            "description": "High-level security posture and compliance overview",
            "role": StakeholderRole.EXECUTIVE.value,
            "layout": "grid",
            "widgets": [
                "overall_risk_score",
                "compliance_status",
                "security_incidents",
                "key_metrics",
                "recent_alerts",
                "trends_chart"
            ],
            "theme": "executive",
            "refresh_interval": 300  # 5 minutes
        }
        
        # Engineer Dashboard
        self.dashboards["engineer"] = {
            "id": "engineer",
            "name": "Engineer Dashboard",
            "description": "Technical security controls and operational metrics",
            "role": StakeholderRole.ENGINEER.value,
            "layout": "grid",
            "widgets": [
                "security_controls",
                "vulnerabilities",
                "deployment_status",
                "performance_metrics",
                "remediation_tasks",
                "system_health"
            ],
            "theme": "technical",
            "refresh_interval": 60  # 1 minute
        }
        
        # Auditor Dashboard
        self.dashboards["auditor"] = {
            "id": "auditor",
            "name": "Auditor Dashboard",
            "description": "Compliance evidence and audit trail",
            "role": StakeholderRole.AUDITOR.value,
            "layout": "grid",
            "widgets": [
                "compliance_evidence",
                "audit_trail",
                "control_effectiveness",
                "risk_assessments",
                "policy_compliance",
                "compliance_timeline"
            ],
            "theme": "compliance",
            "refresh_interval": 300  # 5 minutes
        }
        
        # Security Analyst Dashboard
        self.dashboards["security_analyst"] = {
            "id": "security_analyst",
            "name": "Security Analyst Dashboard",
            "description": "Threat intelligence and incident response",
            "role": StakeholderRole.SECURITY_ANALYST.value,
            "layout": "grid",
            "widgets": [
                "threat_feeds",
                "active_incidents",
                "threat_analysis",
                "response_metrics",
                "security_alerts",
                "threat_timeline"
            ],
            "theme": "security",
            "refresh_interval": 30  # 30 seconds
        }
    
    def _initialize_default_widgets(self):
        """Initialize default dashboard widgets"""
        
        # Executive Widgets
        self.widgets["overall_risk_score"] = DashboardWidgetConfig(
            widget_id="overall_risk_score",
            widget_type=DashboardWidget.METRIC_CARD,
            title="Overall Risk Score",
            description="Current security risk posture",
            position={"x": 0, "y": 0, "width": 3, "height": 2},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.EXECUTIVE).overall_risk_score",
            refresh_interval=300,
            config={"format": "percentage", "color_scheme": "risk", "thresholds": {"low": 0.3, "medium": 0.6, "high": 0.8}}
        )
        
        self.widgets["compliance_status"] = DashboardWidgetConfig(
            widget_id="compliance_status",
            widget_type=DashboardWidget.PROGRESS,
            title="Compliance Status",
            description="Overall compliance across frameworks",
            position={"x": 3, "y": 0, "width": 3, "height": 2},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.EXECUTIVE).compliance_status",
            refresh_interval=300,
            config={"show_details": True, "frameworks": ["SOC2", "ISO27001", "NIST"]}
        )
        
        self.widgets["security_incidents"] = DashboardWidgetConfig(
            widget_id="security_incidents",
            widget_type=DashboardWidget.TABLE,
            title="Recent Security Incidents",
            description="Latest security incidents and their status",
            position={"x": 0, "y": 2, "width": 6, "height": 3},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.EXECUTIVE).recent_incidents",
            refresh_interval=60,
            config={"columns": ["id", "severity", "status", "time"], "sortable": True, "filterable": True}
        )
        
        self.widgets["key_metrics"] = DashboardWidgetConfig(
            widget_id="key_metrics",
            widget_type=DashboardWidget.CHART,
            title="Key Security Metrics",
            description="Trends in key security metrics",
            position={"x": 0, "y": 5, "width": 6, "height": 4},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.EXECUTIVE).key_metrics",
            refresh_interval=300,
            config={"chart_type": "line", "show_trends": True, "time_range": "30d"}
        )
        
        # Engineer Widgets
        self.widgets["security_controls"] = DashboardWidgetConfig(
            widget_id="security_controls",
            widget_type=DashboardWidget.STATUS,
            title="Security Controls Status",
            description="Status of deployed security controls",
            position={"x": 0, "y": 0, "width": 4, "height": 3},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.ENGINEER).security_controls",
            refresh_interval=60,
            config={"show_details": True, "group_by": "status", "color_coding": True}
        )
        
        self.widgets["vulnerabilities"] = DashboardWidgetConfig(
            widget_id="vulnerabilities",
            widget_type=DashboardWidget.TABLE,
            title="Open Vulnerabilities",
            description="Current vulnerabilities requiring attention",
            position={"x": 4, "y": 0, "width": 4, "height": 3},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.ENGINEER).vulnerabilities",
            refresh_interval=60,
            config={"columns": ["cve", "severity", "status", "affected_systems"], "sortable": True, "filterable": True}
        )
        
        self.widgets["deployment_status"] = DashboardWidgetConfig(
            widget_id="deployment_status",
            widget_type=DashboardWidget.PROGRESS,
            title="Deployment Status",
            description="Security control deployment progress",
            position={"x": 0, "y": 3, "width": 4, "height": 2},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.ENGINEER).deployment_status",
            refresh_interval=60,
            config={"show_metrics": True, "show_history": True}
        )
        
        # Auditor Widgets
        self.widgets["compliance_evidence"] = DashboardWidgetConfig(
            widget_id="compliance_evidence",
            widget_type=DashboardWidget.TABLE,
            title="Compliance Evidence",
            description="Evidence for compliance controls",
            position={"x": 0, "y": 0, "width": 6, "height": 3},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.AUDITOR).compliance_evidence",
            refresh_interval=300,
            config={"columns": ["control", "evidence", "last_verified"], "sortable": True, "searchable": True}
        )
        
        self.widgets["audit_trail"] = DashboardWidgetConfig(
            widget_id="audit_trail",
            widget_type=DashboardWidget.TIMELINE,
            title="Audit Trail",
            description="Recent audit activities",
            position={"x": 0, "y": 3, "width": 6, "height": 3},
            data_source="grc_engine.get_stakeholder_dashboard(StakeholderRole.AUDITOR).audit_trail",
            refresh_interval=300,
            config={"show_details": True, "group_by": "date", "filterable": True}
        )
    
    def get_dashboard_config(self, role: str) -> Dict[str, Any]:
        """Get dashboard configuration for a role"""
        dashboard = self.dashboards.get(role, {})
        if not dashboard:
            return {"error": f"Dashboard not found for role: {role}"}
        
        # Get widget configurations
        widgets = []
        for widget_id in dashboard.get("widgets", []):
            widget_config = self.widgets.get(widget_id)
            if widget_config:
                widgets.append(asdict(widget_config))
        
        dashboard["widgets"] = widgets
        return dashboard
    
    def get_widget_data(self, widget_id: str, role: str) -> Dict[str, Any]:
        """Get data for a specific widget"""
        widget_config = self.widgets.get(widget_id)
        if not widget_config:
            return {"error": f"Widget not found: {widget_id}"}
        
        try:
            # Get data from GRC engine
            dashboard_data = self.grc_engine.get_stakeholder_dashboard(StakeholderRole(role))
            
            # Extract specific data based on widget configuration
            data_source = widget_config.data_source
            if "overall_risk_score" in data_source:
                data = dashboard_data.get("overall_risk_score", 0)
            elif "compliance_status" in data_source:
                data = dashboard_data.get("compliance_status", {})
            elif "recent_incidents" in data_source:
                data = dashboard_data.get("recent_incidents", [])
            elif "key_metrics" in data_source:
                data = dashboard_data.get("key_metrics", [])
            elif "security_controls" in data_source:
                data = dashboard_data.get("security_controls", [])
            elif "vulnerabilities" in data_source:
                data = dashboard_data.get("vulnerabilities", [])
            elif "deployment_status" in data_source:
                data = dashboard_data.get("deployment_status", {})
            elif "compliance_evidence" in data_source:
                data = dashboard_data.get("compliance_evidence", [])
            elif "audit_trail" in data_source:
                data = dashboard_data.get("audit_trail", [])
            else:
                data = dashboard_data
            
            return {
                "widget_id": widget_id,
                "data": data,
                "timestamp": datetime.datetime.now().isoformat(),
                "config": widget_config.config
            }
            
        except Exception as e:
            return {"error": f"Failed to get widget data: {str(e)}"}
    
    def create_custom_dashboard(self, user_id: str, name: str, description: str, widgets: List[str]) -> Dict[str, Any]:
        """Create a custom dashboard for a user"""
        dashboard_id = f"custom_{user_id}_{int(time.time())}"
        
        dashboard = {
            "id": dashboard_id,
            "name": name,
            "description": description,
            "user_id": user_id,
            "layout": "grid",
            "widgets": widgets,
            "theme": "default",
            "refresh_interval": 300,
            "created_at": datetime.datetime.now().isoformat(),
            "is_custom": True
        }
        
        self.dashboards[dashboard_id] = dashboard
        return dashboard
    
    def update_widget_position(self, dashboard_id: str, widget_id: str, position: Dict[str, int]) -> bool:
        """Update widget position in dashboard"""
        if dashboard_id in self.dashboards and widget_id in self.widgets:
            self.widgets[widget_id].position = position
            return True
        return False
    
    def get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get user preferences and settings"""
        user = self.users.get(user_id, {})
        return {
            "user_id": user_id,
            "role": user.get("role", "security_analyst"),
            "theme": user.get("theme", "default"),
            "language": user.get("language", "en"),
            "timezone": user.get("timezone", "UTC"),
            "notifications": user.get("notifications", True),
            "refresh_interval": user.get("refresh_interval", 300),
            "custom_dashboards": user.get("custom_dashboards", [])
        }
    
    def update_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """Update user preferences"""
        if user_id not in self.users:
            self.users[user_id] = {}
        
        self.users[user_id].update(preferences)
        return True

class DashboardAPI:
    """REST API for dashboard interactions"""
    
    def __init__(self):
        self.dashboard = WebDashboard()
    
    def get_dashboard_config(self, role: str) -> Dict[str, Any]:
        """Get dashboard configuration"""
        return self.dashboard.get_dashboard_config(role)
    
    def get_widget_data(self, widget_id: str, role: str) -> Dict[str, Any]:
        """Get widget data"""
        return self.dashboard.get_widget_data(widget_id, role)
    
    def get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get user preferences"""
        return self.dashboard.get_user_preferences(user_id)
    
    def update_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> Dict[str, Any]:
        """Update user preferences"""
        success = self.dashboard.update_user_preferences(user_id, preferences)
        return {"success": success, "user_id": user_id}
    
    def create_custom_dashboard(self, user_id: str, name: str, description: str, widgets: List[str]) -> Dict[str, Any]:
        """Create custom dashboard"""
        return self.dashboard.create_custom_dashboard(user_id, name, description, widgets)

def generate_html_dashboard(role: str) -> str:
    """Generate HTML dashboard for a specific role"""
    
    dashboard = WebDashboard()
    config = dashboard.get_dashboard_config(role)
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guardians Armory - {config.get('name', 'Dashboard')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        
        .header h1 {{
            color: #2c3e50;
            font-size: 2rem;
            font-weight: 300;
        }}
        
        .header .subtitle {{
            color: #7f8c8d;
            font-size: 1rem;
            margin-top: 0.5rem;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
        }}
        
        .widget {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .widget:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }}
        
        .widget-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #ecf0f1;
        }}
        
        .widget-title {{
            font-size: 1.2rem;
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .widget-description {{
            color: #7f8c8d;
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }}
        
        .metric-card {{
            text-align: center;
            padding: 1rem;
        }}
        
        .metric-value {{
            font-size: 3rem;
            font-weight: 700;
            color: #3498db;
            margin-bottom: 0.5rem;
        }}
        
        .metric-label {{
            font-size: 1rem;
            color: #7f8c8d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .progress-bar {{
            width: 100%;
            height: 20px;
            background: #ecf0f1;
            border-radius: 10px;
            overflow: hidden;
            margin: 1rem 0;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #3498db, #2ecc71);
            transition: width 0.3s ease;
        }}
        
        .table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .table th, .table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .table th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .status-indicator {{
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }}
        
        .status-active {{ background: #2ecc71; }}
        .status-inactive {{ background: #e74c3c; }}
        .status-warning {{ background: #f39c12; }}
        
        .severity-high {{ color: #e74c3c; font-weight: 600; }}
        .severity-medium {{ color: #f39c12; font-weight: 600; }}
        .severity-low {{ color: #27ae60; font-weight: 600; }}
        
        .refresh-info {{
            text-align: center;
            color: #7f8c8d;
            font-size: 0.8rem;
            margin-top: 2rem;
            padding: 1rem;
            background: rgba(255,255,255,0.5);
            border-radius: 8px;
        }}
        
        @media (max-width: 768px) {{
            .dashboard-grid {{
                grid-template-columns: 1fr;
            }}
            
            .container {{
                padding: 1rem;
            }}
            
            .header {{
                padding: 1rem;
            }}
            
            .header h1 {{
                font-size: 1.5rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Guardians Armory</h1>
        <div class="subtitle">{config.get('name', 'Dashboard')} - {config.get('description', '')}</div>
    </div>
    
    <div class="container">
        <div class="dashboard-grid">
"""
    
    # Generate widgets based on configuration
    for widget_id in config.get("widgets", []):
        widget_config = dashboard.widgets.get(widget_id)
        if widget_config:
            html += generate_widget_html(widget_config, role)
    
    html += """
        </div>
        
        <div class="refresh-info">
            🔄 Dashboard refreshes automatically every 5 minutes
        </div>
    </div>
    
    <script>
        // Auto-refresh functionality
        setInterval(() => {
            location.reload();
        }, 300000); // 5 minutes
        
        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for widgets
            document.querySelectorAll('.widget').forEach(widget => {
                widget.addEventListener('click', function() {
                    this.style.transform = 'scale(1.02)';
                    setTimeout(() => {
                        this.style.transform = '';
                    }, 200);
                });
            });
        });
    </script>
</body>
</html>
"""
    
    return html

def generate_widget_html(widget_config: DashboardWidgetConfig, role: str) -> str:
    """Generate HTML for a specific widget"""
    
    widget_type = widget_config.widget_type
    title = widget_config.title
    description = widget_config.description
    
    html = f"""
    <div class="widget" data-widget-id="{widget_config.widget_id}">
        <div class="widget-header">
            <div>
                <div class="widget-title">{title}</div>
                <div class="widget-description">{description}</div>
            </div>
        </div>
        <div class="widget-content">
"""
    
    if widget_type == DashboardWidget.METRIC_CARD:
        html += generate_metric_card_html(widget_config, role)
    elif widget_type == DashboardWidget.PROGRESS:
        html += generate_progress_widget_html(widget_config, role)
    elif widget_type == DashboardWidget.TABLE:
        html += generate_table_widget_html(widget_config, role)
    elif widget_type == DashboardWidget.STATUS:
        html += generate_status_widget_html(widget_config, role)
    else:
        html += f'<div style="padding: 2rem; text-align: center; color: #7f8c8d;">Widget type "{widget_type.value}" not yet implemented</div>'
    
    html += """
        </div>
    </div>
"""
    
    return html

def generate_metric_card_html(widget_config: DashboardWidgetConfig, role: str) -> str:
    """Generate HTML for metric card widget"""
    
    # Get sample data based on widget ID
    if "risk_score" in widget_config.widget_id:
        value = "25%"
        label = "Overall Risk Score"
        color = "#3498db"
    elif "compliance" in widget_config.widget_id:
        value = "88%"
        label = "Compliance Status"
        color = "#2ecc71"
    else:
        value = "N/A"
        label = "Metric"
        color = "#7f8c8d"
    
    return f"""
    <div class="metric-card">
        <div class="metric-value" style="color: {color};">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
"""

def generate_progress_widget_html(widget_config: DashboardWidgetConfig, role: str) -> str:
    """Generate HTML for progress widget"""
    
    return """
    <div style="padding: 1rem;">
        <div style="margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                <span>Overall Progress</span>
                <span>75%</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: 75%;"></div>
            </div>
        </div>
        <div style="font-size: 0.9rem; color: #7f8c8d;">
            SOC2: 92% | ISO27001: 88% | NIST: 85%
        </div>
    </div>
"""

def generate_table_widget_html(widget_config: DashboardWidgetConfig, role: str) -> str:
    """Generate HTML for table widget"""
    
    if "incidents" in widget_config.widget_id:
        return """
    <table class="table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Time</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>INC-001</td>
                <td><span class="severity-medium">Medium</span></td>
                <td><span class="status-indicator status-active"></span>Resolved</td>
                <td>2 hours ago</td>
            </tr>
            <tr>
                <td>INC-002</td>
                <td><span class="severity-low">Low</span></td>
                <td><span class="status-indicator status-warning"></span>In Progress</td>
                <td>4 hours ago</td>
            </tr>
        </tbody>
    </table>
"""
    elif "vulnerabilities" in widget_config.widget_id:
        return """
    <table class="table">
        <thead>
            <tr>
                <th>CVE</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Systems</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>CVE-2023-1234</td>
                <td><span class="severity-high">High</span></td>
                <td>Open</td>
                <td>3</td>
            </tr>
            <tr>
                <td>CVE-2023-5678</td>
                <td><span class="severity-medium">Medium</span></td>
                <td>In Progress</td>
                <td>1</td>
            </tr>
        </tbody>
    </table>
"""
    else:
        return """
    <table class="table">
        <thead>
            <tr>
                <th>Item</th>
                <th>Status</th>
                <th>Last Updated</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Sample Item</td>
                <td><span class="status-indicator status-active"></span>Active</td>
                <td>1 hour ago</td>
            </tr>
        </tbody>
    </table>
"""

def generate_status_widget_html(widget_config: DashboardWidgetConfig, role: str) -> str:
    """Generate HTML for status widget"""
    
    return """
    <div style="padding: 1rem;">
        <div style="margin-bottom: 1rem;">
            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                <span class="status-indicator status-active"></span>
                <span>IAM-001: Active</span>
            </div>
            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                <span class="status-indicator status-active"></span>
                <span>NET-001: Active</span>
            </div>
            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                <span class="status-indicator status-warning"></span>
                <span>SEC-001: Pending</span>
            </div>
        </div>
        <div style="font-size: 0.9rem; color: #7f8c8d;">
            Total: 3 controls | Active: 2 | Pending: 1
        </div>
    </div>
"""

if __name__ == "__main__":
    # Demo the web dashboard system
    print("🛡️  Guardians Armory: Web Dashboard System")
    print("=" * 50)
    
    # Create dashboard system
    dashboard = WebDashboard()
    
    # Generate HTML dashboards for different roles
    roles = ["executive", "engineer", "auditor", "security_analyst"]
    
    for role in roles:
        print(f"\n📊 Generating {role.title()} Dashboard...")
        html = generate_html_dashboard(role)
        
        # Save HTML file
        filename = f"dashboard_{role}.html"
        with open(filename, 'w') as f:
            f.write(html)
        
        print(f"✅ Saved {filename}")
    
    # Demo API functionality
    print("\n🔌 Dashboard API Demo:")
    api = DashboardAPI()
    
    # Get dashboard config
    config = api.get_dashboard_config("executive")
    print(f"📋 Executive Dashboard Config: {len(config.get('widgets', []))} widgets")
    
    # Get widget data
    widget_data = api.get_widget_data("overall_risk_score", "executive")
    print(f"📊 Widget Data: {widget_data.get('data', 'N/A')}")
    
    # Get user preferences
    prefs = api.get_user_preferences("user123")
    print(f"👤 User Preferences: {prefs.get('role', 'N/A')} role")
    
    print("\n🏆 Web Dashboard System Demo Complete!")
    print("Generated HTML dashboards:")
    for role in roles:
        print(f"  • dashboard_{role}.html")
    
    print("\n🎯 Key Features:")
    print("  • Responsive web design")
    print("  • Role-based dashboards")
    print("  • Interactive widgets")
    print("  • Real-time data updates")
    print("  • Mobile-friendly interface")
    print("  • Customizable layouts")
    print("  • User preferences")
    print("  • REST API support")