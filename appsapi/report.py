"""Report generation module for PDF and HTML exports."""

from datetime import datetime
from owasp import map_to_owasp, get_owasp_summary


def generate_html_report(scan_data: dict) -> str:
    """Generate HTML report from scan results."""
    target = scan_data.get("target_url", "Unknown")
    findings = scan_data.get("findings", [])
    headers = scan_data.get("headers", [])
    risk_score = scan_data.get("risk_score", 0)
    scan_mode = scan_data.get("scan_mode", "quick")
    
    # Count by severity
    severity_counts = {
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high": sum(1 for f in findings if f.get("severity") == "high"),
        "medium": sum(1 for f in findings if f.get("severity") == "medium"),
        "low": sum(1 for f in findings if f.get("severity") == "low"),
        "info": sum(1 for f in findings if f.get("severity") == "info"),
    }
    
    owasp_summary = get_owasp_summary(findings)
    risk_color = "#10b981" if risk_score < 20 else "#f59e0b" if risk_score < 50 else "#ef4444"
    
    # Build findings table rows
    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "info")
        owasp_code = map_to_owasp(f.get("template_id", ""), f.get("name", "")).get("code", "A05")
        findings_rows += f"""
        <tr>
            <td><span class="severity severity-{sev}">{sev}</span></td>
            <td>{f.get("name", "Unknown")}</td>
            <td style="font-family: monospace; font-size: 12px; color: #06b6d4">{f.get("template_id", "N/A")}</td>
            <td><span class="owasp-code">{owasp_code}</span></td>
        </tr>"""
    
    # Build OWASP rows
    owasp_rows = ""
    for code, data in sorted(owasp_summary.items()):
        count = data["count"]
        suffix = "s" if count != 1 else ""
        owasp_rows += f"""
        <div class="owasp-item">
            <span class="owasp-code">{code}</span>
            <span class="owasp-name">{data["name"]}</span>
            <span class="owasp-count">{count} finding{suffix}</span>
        </div>"""
    
    # Build header rows
    header_rows = ""
    for h in headers:
        present = h.get("present", False)
        status_class = "header-present" if present else "header-missing"
        status_text = "Present" if present else "Missing"
        value = h.get("value") or "-"
        header_rows += f"""
        <tr>
            <td style="font-family: monospace">{h.get("name", "")}</td>
            <td><span class="header-status {status_class}">{status_text}</span></td>
            <td style="font-family: monospace; font-size: 12px; color: #6b7280">{value}</td>
            <td style="font-size: 13px">{h.get("recommendation", "")}</td>
        </tr>"""
    
    findings_section = '<p style="color:#6b7280">No vulnerabilities detected.</p>' if not findings else f"""
    <table>
        <thead><tr><th>Severity</th><th>Finding</th><th>Template</th><th>OWASP</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>"""
    
    owasp_section = '<p style="color:#6b7280">No findings to map.</p>' if not owasp_summary else owasp_rows
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconShield Security Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e5e5e5; line-height: 1.6; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 20px; }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 30px; border-bottom: 1px solid #1f1f2e; }}
        .logo {{ font-size: 32px; font-weight: bold; color: #10b981; }}
        .subtitle {{ color: #6b7280; margin-top: 8px; }}
        .target {{ font-family: monospace; color: #06b6d4; font-size: 18px; margin-top: 20px; }}
        .meta {{ display: flex; justify-content: center; gap: 30px; margin-top: 15px; color: #6b7280; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: #12121a; border: 1px solid #1f1f2e; border-radius: 12px; padding: 15px; text-align: center; }}
        .summary-value {{ font-size: 28px; font-weight: bold; }}
        .summary-label {{ color: #6b7280; font-size: 11px; text-transform: uppercase; margin-top: 5px; }}
        .section {{ background: #12121a; border: 1px solid #1f1f2e; border-radius: 12px; margin-bottom: 20px; overflow: hidden; }}
        .section-header {{ padding: 12px 16px; background: #0a0a0f; border-bottom: 1px solid #1f1f2e; font-weight: 600; font-size: 14px; }}
        .section-content {{ padding: 16px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #1f1f2e; }}
        th {{ background: #0a0a0f; color: #6b7280; font-size: 10px; text-transform: uppercase; }}
        .severity {{ padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; }}
        .severity-critical {{ background: rgba(239,68,68,0.2); color: #ef4444; }}
        .severity-high {{ background: rgba(249,115,22,0.2); color: #f97316; }}
        .severity-medium {{ background: rgba(234,179,8,0.2); color: #eab308; }}
        .severity-low {{ background: rgba(16,185,129,0.2); color: #10b981; }}
        .severity-info {{ background: rgba(100,116,139,0.2); color: #64748b; }}
        .owasp-item {{ display: flex; align-items: center; padding: 10px 0; border-bottom: 1px solid #1f1f2e; }}
        .owasp-code {{ background: #06b6d4; color: #000; padding: 3px 6px; border-radius: 4px; font-weight: 600; font-size: 11px; margin-right: 12px; }}
        .owasp-name {{ flex: 1; }}
        .owasp-count {{ background: #1f1f2e; padding: 3px 10px; border-radius: 15px; font-size: 11px; }}
        .header-status {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; }}
        .header-present {{ background: rgba(16,185,129,0.2); color: #10b981; }}
        .header-missing {{ background: rgba(239,68,68,0.2); color: #ef4444; }}
        .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #1f1f2e; color: #6b7280; font-size: 11px; }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">ReconShield</div>
            <p class="subtitle">Security Reconnaissance Report</p>
            <p class="target">{target}</p>
            <div class="meta">
                <span>Mode: {scan_mode.capitalize()}</span>
                <span>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}</span>
            </div>
        </header>

        <div class="summary">
            <div class="summary-card"><div class="summary-value" style="color: {risk_color}">{risk_score}</div><div class="summary-label">Risk Score</div></div>
            <div class="summary-card"><div class="summary-value" style="color: #ef4444">{severity_counts["critical"]}</div><div class="summary-label">Critical</div></div>
            <div class="summary-card"><div class="summary-value" style="color: #f97316">{severity_counts["high"]}</div><div class="summary-label">High</div></div>
            <div class="summary-card"><div class="summary-value" style="color: #eab308">{severity_counts["medium"]}</div><div class="summary-label">Medium</div></div>
            <div class="summary-card"><div class="summary-value" style="color: #10b981">{severity_counts["low"] + severity_counts["info"]}</div><div class="summary-label">Low/Info</div></div>
        </div>

        <section class="section">
            <div class="section-header">Vulnerability Findings ({len(findings)})</div>
            <div class="section-content">{findings_section}</div>
        </section>

        <section class="section">
            <div class="section-header">OWASP Top 10 Mapping</div>
            <div class="section-content">{owasp_section}</div>
        </section>

        <section class="section">
            <div class="section-header">Security Headers</div>
            <div class="section-content">
                <table>
                    <thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Recommendation</th></tr></thead>
                    <tbody>{header_rows}</tbody>
                </table>
            </div>
        </section>

        <footer class="footer">
            <p>Generated by ReconShield - Security Reconnaissance Platform</p>
            <p>2026 Alif. All rights reserved.</p>
        </footer>
    </div>
</body>
</html>"""
    
    return html


def generate_json_report(scan_data: dict) -> dict:
    """Generate JSON report from scan results."""
    findings = scan_data.get("findings", [])
    
    enriched_findings = []
    for f in findings:
        mapping = map_to_owasp(f.get("template_id", ""), f.get("name", ""), f.get("description", ""))
        enriched_findings.append({**f, "owasp": mapping})
    
    return {
        "report_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "target": scan_data.get("target_url"),
        "scan_mode": scan_data.get("scan_mode"),
        "risk_score": scan_data.get("risk_score"),
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
            "info": sum(1 for f in findings if f.get("severity") == "info"),
        },
        "owasp_summary": get_owasp_summary(findings),
        "findings": enriched_findings,
        "security_headers": scan_data.get("headers", []),
    }
