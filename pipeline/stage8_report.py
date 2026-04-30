"""
Stage 8: Report Generation
===========================
Final stage of the subdomain takeover discovery pipeline.
Generates comprehensive HTML dashboard and ZIP archive of all evidence.
"""

import asyncio
import json
import zipfile
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import aiofiles
from jinja2 import Template


# HTML Template for the dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Takeover Report - {{ domain }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #a371f7;
            --accent-orange: #db6d28;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        /* Header */
        .header {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 24px;
        }

        .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .header .domain {
            color: var(--accent-blue);
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 24px;
        }

        .header-meta {
            display: flex;
            gap: 24px;
            margin-top: 16px;
            color: var(--text-secondary);
            font-size: 14px;
        }

        .header-meta span {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }

        .stat-card .number {
            font-size: 42px;
            font-weight: 700;
            line-height: 1.2;
        }

        .stat-card .label {
            color: var(--text-secondary);
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }

        .stat-card.critical .number { color: var(--accent-red); }
        .stat-card.warning .number { color: var(--accent-yellow); }
        .stat-card.success .number { color: var(--accent-green); }
        .stat-card.info .number { color: var(--accent-blue); }

        /* Sections */
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }

        .section-header {
            background: var(--bg-tertiary);
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section-content {
            padding: 20px;
        }

        /* Timeline */
        .timeline {
            position: relative;
            padding-left: 30px;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 8px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border-color);
        }

        .timeline-item {
            position: relative;
            padding-bottom: 20px;
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -26px;
            top: 4px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--accent-green);
            border: 2px solid var(--bg-secondary);
        }

        .timeline-item.failed::before { background: var(--accent-red); }
        .timeline-item.current::before {
            background: var(--accent-blue);
            box-shadow: 0 0 0 4px rgba(88, 166, 255, 0.2);
        }

        .timeline-stage {
            font-weight: 600;
            color: var(--text-primary);
        }

        .timeline-time {
            color: var(--text-muted);
            font-size: 12px;
            font-family: 'SF Mono', Monaco, monospace;
        }

        .timeline-duration {
            color: var(--text-secondary);
            font-size: 13px;
        }

        /* Findings Table */
        .findings-table {
            width: 100%;
            border-collapse: collapse;
        }

        .findings-table th,
        .findings-table td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .findings-table th {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .findings-table tr:hover {
            background: rgba(88, 166, 255, 0.05);
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-critical { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
        .severity-high { background: rgba(210, 153, 34, 0.15); color: var(--accent-yellow); }
        .severity-medium { background: rgba(163, 113, 247, 0.15); color: var(--accent-purple); }
        .severity-low { background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); }
        .severity-info { background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }

        .finding-status {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .status-confirmed { color: var(--accent-red); }
        .status-suspicious { color: var(--accent-yellow); }
        .status-dangling { color: var(--accent-orange); }
        .status-safe { color: var(--accent-green); }

        .subdomain-link {
            color: var(--accent-blue);
            font-family: 'SF Mono', Monaco, monospace;
            text-decoration: none;
        }

        .subdomain-link:hover {
            text-decoration: underline;
        }

        /* DNS Records */
        .dns-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 16px;
        }

        .dns-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
        }

        .dns-card .subdomain {
            color: var(--accent-blue);
            font-family: 'SF Mono', Monaco, monospace;
            font-weight: 600;
            margin-bottom: 12px;
            display: block;
        }

        .dns-record {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }

        .dns-record:last-child { border-bottom: none; }

        .dns-record .type {
            color: var(--text-muted);
            font-family: 'SF Mono', Monaco, monospace;
        }

        .dns-record .value {
            color: var(--text-primary);
            font-family: 'SF Mono', Monaco, monospace;
            text-align: right;
            word-break: break-all;
        }

        /* Evidence Gallery */
        .evidence-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }

        .evidence-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }

        .evidence-card img {
            width: 100%;
            height: 200px;
            object-fit: cover;
            display: block;
        }

        .evidence-info {
            padding: 12px;
        }

        .evidence-info h4 {
            color: var(--accent-blue);
            font-family: 'SF Mono', Monaco, monospace;
            margin-bottom: 8px;
        }

        .evidence-meta {
            font-size: 12px;
            color: var(--text-muted);
        }

        /* Charts */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }

        .chart-container {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }

        .chart-title {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 16px;
            color: var(--text-secondary);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            font-size: 13px;
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }

        /* Code blocks */
        pre, code {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            background: var(--bg-tertiary);
            border-radius: 4px;
        }

        pre {
            padding: 16px;
            overflow-x: auto;
            font-size: 13px;
        }

        .nuclei-finding {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 12px;
        }

        .nuclei-finding .info {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
        }

        .nuclei-finding .template {
            color: var(--accent-purple);
            font-weight: 600;
        }

        .nuclei-finding .description {
            color: var(--text-secondary);
            font-size: 14px;
        }

        .nuclei-finding .matcher {
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid var(--border-color);
            font-size: 12px;
            color: var(--text-muted);
        }

        /* Tags */
        .tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            margin-right: 4px;
        }

        /* Pagination */
        .pagination {
            display: flex;
            justify-content: center;
            gap: 8px;
            margin-top: 20px;
        }

        .pagination button {
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            border-radius: 6px;
            cursor: pointer;
        }

        .pagination button:hover {
            background: var(--border-color);
        }

        .pagination button.active {
            background: var(--accent-blue);
            border-color: var(--accent-blue);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Subdomain Takeover Discovery Report</h1>
            <span class="domain">{{ domain }}</span>
            <div class="header-meta">
                <span>Generated: {{ timestamp }}</span>
                <span>Pipeline ID: {{ pipeline_id }}</span>
                <span>Duration: {{ total_duration }}</span>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="stat-card info">
                <div class="number">{{ stats.total_subdomains }}</div>
                <div class="label">Total Subdomains</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{{ stats.suspicious }}</div>
                <div class="label">Suspicious</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{{ stats.dangling }}</div>
                <div class="label">Dangling DNS</div>
            </div>
            <div class="stat-card success">
                <div class="number">{{ stats.confirmed }}</div>
                <div class="label">Confirmed Takeovers</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.nuclei_findings }}</div>
                <div class="label">Nuclei Findings</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.cloud_cnames }}</div>
                <div class="label">Cloud CNAMEs</div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="section">
            <div class="section-header">
                <span>📊</span> Pipeline Statistics
            </div>
            <div class="section-content">
                <div class="charts-grid">
                    <div class="chart-container">
                        <div class="chart-title">Subdomain Status Distribution</div>
                        <canvas id="statusChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <div class="chart-title">Pipeline Stage Durations</div>
                        <canvas id="durationChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Timeline -->
        <div class="section">
            <div class="section-header">
                <span>⏱️</span> Pipeline Execution Timeline
            </div>
            <div class="section-content">
                <div class="timeline">
                    {% for stage in timeline %}
                    <div class="timeline-item {% if stage.status == 'failed' %}failed{% elif stage.status == 'current' %}current{% endif %}">
                        <div class="timeline-stage">{{ stage.name }}</div>
                        <div class="timeline-time">{{ stage.start_time }}</div>
                        <div class="timeline-duration">{{ stage.duration }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- Confirmed Findings -->
        {% if confirmed_findings %}
        <div class="section">
            <div class="section-header">
                <span>🚨</span> Confirmed Takeover Vulnerabilities
            </div>
            <div class="section-content">
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>Provider</th>
                            <th>CNAME</th>
                            <th>Nuclei Template</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in confirmed_findings %}
                        <tr>
                            <td>
                                <a href="http://{{ finding.subdomain }}" target="_blank" class="subdomain-link">
                                    {{ finding.subdomain }}
                                </a>
                            </td>
                            <td>{{ finding.provider }}</td>
                            <td><code>{{ finding.cname }}</code></td>
                            <td><span class="severity-badge severity-critical">{{ finding.template }}</span></td>
                            <td>
                                {% if finding.screenshot %}
                                <a href="{{ finding.screenshot }}" target="_blank">Screenshot</a>
                                {% endif %}
                                {% if finding.dns_records %}
                                <a href="{{ finding.dns_records }}" target="_blank">DNS Records</a>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- Suspicious Findings -->
        {% if suspicious_findings %}
        <div class="section">
            <div class="section-header">
                <span>⚠️</span> Suspicious Takeover Candidates
            </div>
            <div class="section-content">
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>Provider</th>
                            <th>CNAME</th>
                            <th>Status</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in suspicious_findings %}
                        <tr>
                            <td>
                                <a href="http://{{ finding.subdomain }}" target="_blank" class="subdomain-link">
                                    {{ finding.subdomain }}
                                </a>
                            </td>
                            <td>{{ finding.provider }}</td>
                            <td><code>{{ finding.cname }}</code></td>
                            <td><span class="severity-badge severity-high">{{ finding.status }}</span></td>
                            <td>{{ finding.details }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- DNS Records -->
        {% if dns_records %}
        <div class="section">
            <div class="section-header">
                <span>🌐</span> DNS Record Analysis
            </div>
            <div class="section-content">
                <div class="dns-grid">
                    {% for record in dns_records %}
                    <div class="dns-card">
                        <span class="subdomain">{{ record.subdomain }}</span>
                        {% for r in record.records %}
                        <div class="dns-record">
                            <span class="type">{{ r.type }}</span>
                            <span class="value">{{ r.value }}</span>
                        </div>
                        {% endfor %}
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Nuclei Findings -->
        {% if nuclei_findings %}
        <div class="section">
            <div class="section-header">
                <span>🔬</span> Nuclei Scan Results
            </div>
            <div class="section-content">
                {% for finding in nuclei_findings %}
                <div class="nuclei-finding">
                    <div class="info">
                        <span class="template">{{ finding.template }}</span>
                        <span class="severity-badge severity-{{ finding.severity }}">{{ finding.severity }}</span>
                    </div>
                    <div class="description">{{ finding.description }}</div>
                    <div class="matcher">Matched: {{ finding.matched_at }}</div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <!-- Evidence Gallery -->
        {% if evidence %}
        <div class="section">
            <div class="section-header">
                <span>📸</span> Evidence Gallery
            </div>
            <div class="section-content">
                <div class="evidence-grid">
                    {% for item in evidence %}
                    <div class="evidence-card">
                        <img src="{{ item.screenshot }}" alt="{{ item.subdomain }}" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%2321262d%22 width=%22100%22 height=%22100%22/><text x=%2250%22 y=%2255%22 text-anchor=%22middle%22 fill=%22%236e7681%22 font-size=%2212%22>No Screenshot</text></svg>'">
                        <div class="evidence-info">
                            <h4>{{ item.subdomain }}</h4>
                            <div class="evidence-meta">
                                {{ item.provider }} | {{ item.timestamp }}
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Footer -->
        <div class="footer">
            Generated by Recon Bot | Subdomain Takeover Discovery Pipeline<br>
            Report ID: {{ pipeline_id }} | {{ timestamp }}
        </div>
    </div>

    <script>
        // Status Distribution Chart
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        new Chart(statusCtx, {
            type: 'doughnut',
            data: {
                labels: {{ chart_data.status_labels | tojson }},
                datasets: [{
                    data: {{ chart_data.status_values | tojson }},
                    backgroundColor: [
                        '#f85149',
                        '#d29922',
                        '#58a6ff',
                        '#3fb950',
                        '#a371f7'
                    ],
                    borderColor: '#161b22',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#8b949e', padding: 20 }
                    }
                }
            }
        });

        // Stage Durations Chart
        const durationCtx = document.getElementById('durationChart').getContext('2d');
        new Chart(durationCtx, {
            type: 'bar',
            data: {
                labels: {{ chart_data.stage_labels | tojson }},
                datasets: [{
                    label: 'Duration (seconds)',
                    data: {{ chart_data.stage_durations | tojson }},
                    backgroundColor: '#58a6ff',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: '#30363d' },
                        ticks: { color: '#8b949e' }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#e6edf3' }
                    }
                }
            }
        });
    </script>
</body>
</html>
"""


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def format_timestamp(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


async def generate_html_report(
    domain: str,
    output_dir: str,
    pipeline_data: dict,
    pipeline_id: str
) -> str:
    """Generate comprehensive HTML dashboard using Jinja2 template."""

    # Extract data from pipeline stages
    stage_data = pipeline_data.get("stages", {})
    stage1 = stage_data.get("stage1", {})
    stage3 = stage_data.get("stage3", {})
    stage4 = stage_data.get("stage4", {})
    stage5 = stage_data.get("stage5", {})
    stage6 = stage_data.get("stage6", {})
    stage7 = stage_data.get("stage7", {})

    # Calculate statistics
    total_subdomains = len(stage1.get("subdomains", []))
    suspicious = len(stage3.get("suspicious_cnames", []))
    dangling = len(stage4.get("dangling", []))
    confirmed = len(stage6.get("confirmed_takeovers", []))
    nuclei_findings = len(stage6.get("nuclei_findings", []))
    cloud_cnames = len(stage3.get("cloud_cnames", []))

    # Build timeline
    timeline = []
    for stage_name, stage_info in stage_data.items():
        if isinstance(stage_info, dict):
            timeline.append({
                "name": stage_info.get("name", stage_name),
                "start_time": stage_info.get("start_time", "N/A"),
                "duration": format_duration(stage_info.get("duration", 0)),
                "status": stage_info.get("status", "completed")
            })

    # Confirmed findings
    confirmed_findings = []
    for takeover in stage6.get("confirmed_takeovers", []):
        finding = {
            "subdomain": takeover.get("subdomain", ""),
            "provider": takeover.get("provider", "Unknown"),
            "cname": takeover.get("cname", ""),
            "template": takeover.get("template_id", "N/A"),
            "screenshot": None,
            "dns_records": None
        }

        # Link to evidence silo
        subdomain_slug = takeover.get("subdomain", "").replace(".", "_")
        silo_path = os.path.join(output_dir, "..", subdomain_slug)
        if os.path.exists(silo_path):
            screenshot_path = os.path.join(silo_path, f"{subdomain_slug}.png")
            if os.path.exists(screenshot_path):
                finding["screenshot"] = screenshot_path
            dns_path = os.path.join(silo_path, f"{subdomain_slug}_dns.txt")
            if os.path.exists(dns_path):
                finding["dns_records"] = dns_path

        confirmed_findings.append(finding)

    # Suspicious findings
    suspicious_findings = []
    for item in stage4.get("dangling", []):
        suspicious_findings.append({
            "subdomain": item.get("subdomain", ""),
            "provider": item.get("provider", "Unknown"),
            "cname": item.get("cname", ""),
            "status": "Dangling",
            "details": item.get("reason", "NXDOMAIN confirmed")
        })

    # DNS records
    dns_records = []
    for record_set in stage7.get("dns_records", []):
        dns_records.append({
            "subdomain": record_set.get("subdomain", ""),
            "records": record_set.get("records", [])
        })

    # Nuclei findings
    nuclei_findings_list = []
    for finding in stage6.get("nuclei_findings", []):
        nuclei_findings_list.append({
            "template": finding.get("template_id", "unknown"),
            "severity": finding.get("severity", "info"),
            "description": finding.get("description", ""),
            "matched_at": finding.get("matched_at", "")
        })

    # Evidence gallery
    evidence = []
    for silo_dir in stage7.get("evidence_silos", []):
        if os.path.isdir(silo_dir):
            subdomain = os.path.basename(silo_dir).replace("_", ".")
            screenshot = os.path.join(silo_dir, f"{os.path.basename(silo_dir)}.png")
            if os.path.exists(screenshot):
                evidence.append({
                    "subdomain": subdomain,
                    "screenshot": screenshot,
                    "provider": "Unknown",
                    "timestamp": format_timestamp(datetime.now())
                })

    # Chart data
    chart_data = {
        "status_labels": ["Confirmed", "Suspicious", "Dangling", "Resolved", "Cloud CNAMEs"],
        "status_values": [confirmed, suspicious, dangling, total_subdomains - suspicious - dangling - confirmed, cloud_cnames],
        "stage_labels": [t["name"] for t in timeline],
        "stage_durations": [t.get("duration", 0) for t in timeline]
    }

    # Calculate total duration
    total_duration = sum(t.get("duration", 0) for t in timeline)
    if timeline:
        total_duration_str = format_duration(total_duration)
    else:
        total_duration_str = "N/A"

    # Render template
    template = Template(DASHBOARD_TEMPLATE)
    html_content = template.render(
        domain=domain,
        pipeline_id=pipeline_id,
        timestamp=format_timestamp(datetime.now()),
        total_duration=total_duration_str,
        stats={
            "total_subdomains": total_subdomains,
            "suspicious": suspicious,
            "dangling": dangling,
            "confirmed": confirmed,
            "nuclei_findings": nuclei_findings,
            "cloud_cnames": cloud_cnames
        },
        timeline=timeline,
        chart_data=chart_data,
        confirmed_findings=confirmed_findings,
        suspicious_findings=suspicious_findings,
        dns_records=dns_records[:20],  # Limit to first 20
        nuclei_findings=nuclei_findings_list[:50],  # Limit to first 50
        evidence=evidence[:12]  # Limit to first 12
    )

    return html_content


async def create_zip_archive(
    domain: str,
    output_dir: str,
    pipeline_data: dict,
    report_path: str
) -> str:
    """Create ZIP archive containing all evidence and reports."""

    archive_name = f"{domain}_report.zip"
    archive_path = os.path.join(output_dir, archive_name)

    # Collect all files to archive
    files_to_archive = []

    # Add HTML report
    if os.path.exists(report_path):
        files_to_archive.append((report_path, "dashboard.html"))

    # Add domain directory contents
    domain_dir = os.path.dirname(output_dir.rstrip("/"))
    for root, dirs, files in os.walk(domain_dir):
        # Skip the final report directory itself
        if domain + "_Final_Report" in root:
            continue

        for file in files:
            file_path = os.path.join(root, file)
            # Calculate relative path for archive
            rel_path = os.path.relpath(file_path, domain_dir)
            files_to_archive.append((file_path, rel_path))

    # Add metadata.json
    metadata = {
        "domain": domain,
        "pipeline_id": pipeline_data.get("pipeline_id", "unknown"),
        "generated_at": datetime.now().isoformat(),
        "stats": pipeline_data.get("stats", {}),
        "stages": list(pipeline_data.get("stages", {}).keys()),
        "version": "1.0.0"
    }

    # Write archive
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add metadata
        metadata_json = json.dumps(metadata, indent=2)
        zf.writestr("metadata.json", metadata_json)

        # Add all collected files
        for file_path, arcname in files_to_archive:
            try:
                if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
                    zf.write(file_path, arcname)
            except (OSError, IOError):
                # Skip files that can't be read
                continue

    return archive_path


async def save_html_report(html_content: str, output_path: str) -> None:
    """Save HTML content to file asynchronously."""
    async with aiofiles.open(output_path, "w", encoding="utf-8") as f:
        await f.write(html_content)


async def run_stage8(domain: str, output_dir: str, all_pipeline_data: dict) -> dict:
    """
    Stage 8: Report Generation

    Generates comprehensive HTML report and ZIP archive of all evidence.

    Args:
        domain: Target domain
        output_dir: Base output directory for the domain
        all_pipeline_data: Dictionary containing data from all pipeline stages

    Returns:
        dict with paths to generated report files
    """

    # Ensure final report directory exists
    report_dir = os.path.join(output_dir, f"{domain}_Final_Report")
    os.makedirs(report_dir, exist_ok=True)

    # Generate pipeline ID from first stage data if available
    pipeline_id = all_pipeline_data.get("pipeline_id", f"{domain}-{int(datetime.now().timestamp())}")

    # Run report generation and archive creation concurrently
    report_path = os.path.join(report_dir, "dashboard.html")

    # Generate HTML report
    html_content = await generate_html_report(
        domain=domain,
        output_dir=output_dir,
        pipeline_data=all_pipeline_data,
        pipeline_id=pipeline_id
    )

    # Save HTML report
    await save_html_report(html_content, report_path)

    # Create ZIP archive (includes the HTML report)
    archive_path = await create_zip_archive(
        domain=domain,
        output_dir=report_dir,
        pipeline_data=all_pipeline_data,
        report_path=report_path
    )

    # Return result summary
    result = {
        "report_directory": report_dir,
        "dashboard_path": report_path,
        "archive_path": archive_path,
        "pipeline_id": pipeline_id,
        "domain": domain,
        "generated_at": datetime.now().isoformat()
    }

    # Add statistics to result
    stage6 = all_pipeline_data.get("stages", {}).get("stage6", {})
    stage7 = all_pipeline_data.get("stages", {}).get("stage7", {})

    result["summary"] = {
        "confirmed_takeovers": len(stage6.get("confirmed_takeovers", [])),
        "suspicious_count": len(all_pipeline_data.get("stages", {}).get("stage3", {}).get("suspicious_cnames", [])),
        "nuclei_findings": len(stage6.get("nuclei_findings", [])),
        "evidence_silos": len(stage7.get("evidence_silos", []))
    }

    return result


# Synchronous wrapper for non-async contexts
def run_stage8_sync(domain: str, output_dir: str, all_pipeline_data: dict) -> dict:
    """Synchronous wrapper for run_stage8."""
    return asyncio.run(run_stage8(domain, output_dir, all_pipeline_data))


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) >= 3:
        domain = sys.argv[1]
        output_dir = sys.argv[2]

        # Sample pipeline data structure
        sample_data = {
            "pipeline_id": f"demo-{int(datetime.now().timestamp())}",
            "stages": {
                "stage1": {
                    "name": "Passive Discovery",
                    "start_time": format_timestamp(datetime.now()),
                    "duration": 45.2,
                    "status": "completed",
                    "subdomains": ["sub1.example.com", "sub2.example.com"]
                },
                "stage6": {
                    "name": "Nuclei Confirmation",
                    "confirmed_takeovers": [],
                    "nuclei_findings": []
                },
                "stage7": {
                    "name": "Evidence Collection",
                    "evidence_silos": [],
                    "dns_records": []
                }
            },
            "stats": {}
        }

        result = run_stage8_sync(domain, output_dir, sample_data)
        print(json.dumps(result, indent=2))
    else:
        print(f"Usage: {sys.argv[0]} <domain> <output_dir>")
