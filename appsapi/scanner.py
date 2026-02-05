import subprocess
import json
from pathlib import Path
from typing import Optional

def run_nuclei_scan(target_url: str, scan_id: str, templates: str = "technologies,exposures") -> list:
    """Run Nuclei scan with specified templates."""
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "nuclei.jsonl"

    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-o", str(output_file),
        "-tags", templates,
        "-severity", "info,low,medium,high,critical",
        "-stats",
        "-timeout", "15",
        "-retries", "1"
    ]

    try:
        subprocess.run(cmd, check=False, timeout=120)
    except subprocess.TimeoutExpired:
        pass

    findings = []
    if output_file.exists():
        for line in output_file.read_text(encoding="utf-8").splitlines():
            try:
                findings.append(json.loads(line))
            except:
                pass
    return findings


def run_header_scan(target_url: str) -> dict:
    """Run security header analysis."""
    import requests
    try:
        response = requests.head(target_url, timeout=10, allow_redirects=True)
        return dict(response.headers)
    except Exception as e:
        return {"error": str(e)}


def run_network_scan(target_url: str, scan_id: str) -> list:
    """Run network scan for port detection."""
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "network.jsonl"
    
    # Extract domain from URL
    from urllib.parse import urlparse
    domain = urlparse(target_url).netloc or target_url
    
    cmd = [
        "nuclei",
        "-u", domain,
        "-jsonl",
        "-o", str(output_file),
        "-tags", "network,ssl,dns",
        "-severity", "info,low,medium,high,critical",
        "-timeout", "10"
    ]

    try:
        subprocess.run(cmd, check=False, timeout=90)
    except subprocess.TimeoutExpired:
        pass

    findings = []
    if output_file.exists():
        for line in output_file.read_text(encoding="utf-8").splitlines():
            try:
                findings.append(json.loads(line))
            except:
                pass
    return findings
