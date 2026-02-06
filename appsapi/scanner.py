"""
ReconScience Security Scanner
Comprehensive scanning with Nuclei (when available) and Python-based fallback.
"""
import subprocess
import json
import os
import re
import requests
from pathlib import Path
from typing import Optional, List, Dict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# User agent for requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Check if Nuclei is available
def is_nuclei_available() -> bool:
    try:
        result = subprocess.run(["nuclei", "-version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

NUCLEI_AVAILABLE = is_nuclei_available()


# ============== Technology Detection ==============
# Tech signatures for detection
TECH_SIGNATURES = {
    "WordPress": {
        "patterns": [r"wp-content", r"wp-includes", r"wordpress", r"/wp-json/"],
        "headers": {"X-Powered-By": "WordPress"},
        "type": "CMS"
    },
    "Joomla": {
        "patterns": [r"/media/jui/", r"Joomla!", r"/administrator/"],
        "type": "CMS"
    },
    "Drupal": {
        "patterns": [r"Drupal", r"/sites/default/", r"drupal.js"],
        "headers": {"X-Generator": "Drupal"},
        "type": "CMS"
    },
    "React": {
        "patterns": [r"react", r"__REACT", r"data-reactroot", r"_reactRootContainer"],
        "type": "Frontend Framework"
    },
    "Vue.js": {
        "patterns": [r"vue", r"__VUE__", r"data-v-"],
        "type": "Frontend Framework"
    },
    "Angular": {
        "patterns": [r"ng-version", r"angular", r"ng-app"],
        "type": "Frontend Framework"
    },
    "Next.js": {
        "patterns": [r"__NEXT_DATA__", r"_next/static", r"next/router"],
        "type": "Frontend Framework"
    },
    "jQuery": {
        "patterns": [r"jquery", r"jQuery"],
        "type": "JavaScript Library"
    },
    "Bootstrap": {
        "patterns": [r"bootstrap", r"class=\"container", r"class=\"row"],
        "type": "CSS Framework"
    },
    "Tailwind CSS": {
        "patterns": [r"tailwind", r"class=\"flex ", r"class=\"bg-"],
        "type": "CSS Framework"
    },
    "PHP": {
        "headers": {"X-Powered-By": "PHP"},
        "type": "Backend"
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": "ASP.NET", "X-AspNet-Version": ""},
        "type": "Backend"
    },
    "Express": {
        "headers": {"X-Powered-By": "Express"},
        "type": "Backend"
    },
    "Nginx": {
        "headers": {"Server": "nginx"},
        "type": "Web Server"
    },
    "Apache": {
        "headers": {"Server": "Apache"},
        "type": "Web Server"
    },
    "Cloudflare": {
        "headers": {"Server": "cloudflare", "CF-RAY": ""},
        "type": "CDN/Security"
    },
    "Google Analytics": {
        "patterns": [r"google-analytics", r"gtag", r"UA-\d+-\d+", r"G-\w+"],
        "type": "Analytics"
    },
    "Google Tag Manager": {
        "patterns": [r"googletagmanager", r"GTM-\w+"],
        "type": "Analytics"
    },
}


def detect_technologies(url: str, html: str, headers: Dict) -> List[Dict]:
    """Detect technologies from HTML content and headers."""
    detected = []
    html_lower = html.lower() if html else ""
    
    for tech_name, config in TECH_SIGNATURES.items():
        found = False
        version = None
        
        # Check patterns in HTML
        if "patterns" in config and html:
            for pattern in config["patterns"]:
                if re.search(pattern, html, re.IGNORECASE):
                    found = True
                    break
        
        # Check headers
        if "headers" in config:
            for header_name, header_value in config["headers"].items():
                actual_value = headers.get(header_name, "")
                if header_value:
                    if header_value.lower() in actual_value.lower():
                        found = True
                        # Try to extract version
                        version_match = re.search(r"[\d.]+", actual_value)
                        if version_match:
                            version = version_match.group()
                elif actual_value:  # Header exists, no specific value needed
                    if header_name.lower() in [h.lower() for h in headers.keys()]:
                        found = True
        
        if found:
            detected.append({
                "name": tech_name,
                "type": config.get("type", "Technology"),
                "version": version,
                "confidence": "high"
            })
    
    return detected


# ============== Security Checks ==============
SECURITY_CHECKS = [
    {
        "id": "exposed-git",
        "name": "Exposed .git directory",
        "path": "/.git/config",
        "severity": "high",
        "check": lambda r: "[core]" in r.text or "repositoryformatversion" in r.text,
        "description": "Git configuration file exposed, may leak source code"
    },
    {
        "id": "exposed-env",
        "name": "Exposed .env file",
        "path": "/.env",
        "severity": "critical",
        "check": lambda r: "=" in r.text and len(r.text) < 10000 and r.status_code == 200,
        "description": "Environment file exposed, may contain credentials"
    },
    {
        "id": "exposed-htaccess",
        "name": "Exposed .htaccess",
        "path": "/.htaccess",
        "severity": "medium",
        "check": lambda r: "RewriteRule" in r.text or "Deny from" in r.text,
        "description": "Apache configuration file exposed"
    },
    {
        "id": "exposed-wp-config",
        "name": "WordPress Config Backup",
        "path": "/wp-config.php.bak",
        "severity": "critical",
        "check": lambda r: "DB_PASSWORD" in r.text,
        "description": "WordPress configuration backup exposed"
    },
    {
        "id": "exposed-debug",
        "name": "Debug Mode Enabled",
        "path": "/",
        "severity": "medium",
        "check": lambda r: "Traceback" in r.text or "DEBUG = True" in r.text or "stack trace" in r.text.lower(),
        "description": "Debug mode appears to be enabled"
    },
    {
        "id": "exposed-phpinfo",
        "name": "PHPInfo Exposed",
        "path": "/phpinfo.php",
        "severity": "medium",
        "check": lambda r: "PHP Version" in r.text and "phpinfo()" in r.text,
        "description": "PHPInfo page exposed, reveals server configuration"
    },
    {
        "id": "exposed-robots",
        "name": "Sensitive Robots.txt",
        "path": "/robots.txt",
        "severity": "info",
        "check": lambda r: "admin" in r.text.lower() or "login" in r.text.lower() or "backup" in r.text.lower(),
        "description": "Robots.txt reveals potentially sensitive paths"
    },
    {
        "id": "exposed-backup",
        "name": "Backup File Found",
        "path": "/backup.zip",
        "severity": "high",
        "check": lambda r: r.status_code == 200 and len(r.content) > 100,
        "description": "Backup file publicly accessible"
    },
    {
        "id": "exposed-sql",
        "name": "SQL Dump Exposed",
        "path": "/database.sql",
        "severity": "critical",
        "check": lambda r: "CREATE TABLE" in r.text or "INSERT INTO" in r.text,
        "description": "Database dump file exposed"
    },
    {
        "id": "directory-listing",
        "name": "Directory Listing Enabled",
        "path": "/backup/",
        "severity": "medium",
        "check": lambda r: "Index of" in r.text or "Directory listing" in r.text,
        "description": "Directory listing enabled, may expose files"
    },
    {
        "id": "exposed-readme",
        "name": "README Exposed",
        "path": "/README.md",
        "severity": "info",
        "check": lambda r: r.status_code == 200 and len(r.text) > 50,
        "description": "README file exposed, may reveal project info"
    },
    {
        "id": "exposed-changelog",
        "name": "Changelog Exposed",
        "path": "/CHANGELOG.md",
        "severity": "info",
        "check": lambda r: r.status_code == 200 and ("version" in r.text.lower() or "changelog" in r.text.lower()),
        "description": "Changelog exposed, reveals version history"
    },
]

# Additional paths to check
COMMON_PATHS = [
    "/admin", "/login", "/administrator", "/wp-admin", "/phpmyadmin",
    "/admin.php", "/config.php", "/config.json", "/server-status",
    "/.svn/entries", "/.DS_Store", "/crossdomain.xml"
]


def check_security_issue(url: str, check: Dict) -> Optional[Dict]:
    """Check a single security issue."""
    try:
        full_url = url.rstrip("/") + check["path"]
        response = requests.get(
            full_url, 
            timeout=10, 
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False,
            verify=False
        )
        
        if check["check"](response):
            return {
                "template_id": check["id"],
                "name": check["name"],
                "severity": check["severity"],
                "matched_at": full_url,
                "description": check["description"],
                "category": "exposure"
            }
    except:
        pass
    return None


def run_security_checks(url: str) -> List[Dict]:
    """Run all security checks in parallel."""
    findings = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_security_issue, url, check): check for check in SECURITY_CHECKS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
    
    return findings


# ============== Header Analysis ==============
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "risk": "high",
        "description": "Prevents XSS and code injection attacks",
        "recommendation": "Add CSP header with strict policy"
    },
    "Strict-Transport-Security": {
        "risk": "high",
        "description": "Forces HTTPS connections",
        "recommendation": "Add HSTS header: max-age=31536000; includeSubDomains"
    },
    "X-Frame-Options": {
        "risk": "medium",
        "description": "Prevents clickjacking attacks",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "risk": "medium",
        "description": "Prevents MIME-type sniffing",
        "recommendation": "Add X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "risk": "medium",
        "description": "Controls referrer information",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "risk": "low",
        "description": "Controls browser features",
        "recommendation": "Add Permissions-Policy to restrict sensitive features"
    },
    "X-XSS-Protection": {
        "risk": "low",
        "description": "Legacy XSS filter",
        "recommendation": "Add X-XSS-Protection: 1; mode=block"
    },
    "Cross-Origin-Opener-Policy": {
        "risk": "low",
        "description": "Isolates browsing context",
        "recommendation": "Add COOP header for enhanced security"
    },
    "Cross-Origin-Resource-Policy": {
        "risk": "low",
        "description": "Controls resource sharing",
        "recommendation": "Add CORP header: same-origin or cross-origin"
    },
}


def analyze_security_headers(url: str) -> List[Dict]:
    """Analyze security headers of a URL."""
    results = []
    
    try:
        response = requests.get(
            url,
            timeout=15,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            verify=False
        )
        
        for header_name, config in SECURITY_HEADERS.items():
            value = response.headers.get(header_name)
            present = value is not None
            
            results.append({
                "name": header_name,
                "present": present,
                "value": value[:100] if value else None,
                "risk": config["risk"] if not present else "low",
                "description": config["description"],
                "recommendation": f"✓ {value[:50]}..." if present else config["recommendation"]
            })
        
        # Add server info
        server = response.headers.get("Server", "Unknown")
        if server and server != "Unknown":
            results.append({
                "name": "Server",
                "present": True,
                "value": server,
                "risk": "info",
                "description": "Web server identification",
                "recommendation": "Consider removing server banner"
            })
            
    except Exception as e:
        print(f"[Headers] Error analyzing {url}: {e}")
        # Return default headers with unknown status
        for header_name, config in SECURITY_HEADERS.items():
            results.append({
                "name": header_name,
                "present": False,
                "value": None,
                "risk": "unknown",
                "description": config["description"],
                "recommendation": "Could not check - connection error"
            })
    
    return results


# ============== Main Scan Functions ==============
def run_nuclei_scan(
    target_url: str, 
    scan_id: str, 
    templates: str = "",
    scan_mode: str = "quick",
    categories: Optional[List[str]] = None
) -> List[Dict]:
    """
    Run comprehensive security scan.
    Uses Nuclei if available, otherwise falls back to Python-based scanning.
    """
    print(f"[Scanner] Starting {scan_mode} scan on {target_url}")
    print(f"[Scanner] Nuclei available: {NUCLEI_AVAILABLE}")
    
    findings = []
    
    # Always run Python-based security checks (fast and reliable)
    print("[Scanner] Running security checks...")
    security_findings = run_security_checks(target_url)
    findings.extend(security_findings)
    print(f"[Scanner] Found {len(security_findings)} security issues")
    
    # If Nuclei is available, run additional scans
    if NUCLEI_AVAILABLE:
        print("[Scanner] Running Nuclei scan...")
        nuclei_findings = run_nuclei_scan_internal(target_url, scan_id, scan_mode, categories)
        findings.extend(nuclei_findings)
        print(f"[Scanner] Nuclei found {len(nuclei_findings)} additional findings")
    
    print(f"[Scanner] Total findings: {len(findings)}")
    return findings


def run_nuclei_scan_internal(target_url: str, scan_id: str, scan_mode: str, categories: Optional[List[str]]) -> List[Dict]:
    """Internal function to run actual Nuclei scan."""
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "nuclei_results.jsonl"
    
    # Build tags based on mode
    tags_map = {
        "quick": "tech,exposure,misconfiguration",
        "full": "cve,vulnerability,exposure,misconfiguration,takeover",
        "network": "network,ssl,dns",
        "custom": ",".join(categories) if categories else "cve,misconfiguration"
    }
    
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-o", str(output_file),
        "-tags", tags_map.get(scan_mode, tags_map["quick"]),
        "-severity", "info,low,medium,high,critical",
        "-silent",
        "-timeout", "15",
        "-retries", "2"
    ]
    
    try:
        subprocess.run(cmd, check=False, timeout=300, capture_output=True)
    except Exception as e:
        print(f"[Nuclei] Error: {e}")
        return []
    
    findings = []
    if output_file.exists():
        for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    findings.append(data)
                except:
                    pass
    
    return findings


def run_header_scan(target_url: str) -> Dict:
    """Run security header analysis."""
    results = analyze_security_headers(target_url)
    return {"results": results, "total": len(results)}


def run_network_scan(target_url: str, scan_id: str) -> List[Dict]:
    """Run network scan (placeholder for now)."""
    # Network scanning requires specialized tools
    return []


def run_tech_detection(target_url: str, scan_id: str) -> List[Dict]:
    """Detect technologies used by the target."""
    print(f"[Tech] Detecting technologies for {target_url}")
    
    try:
        response = requests.get(
            target_url,
            timeout=15,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            verify=False
        )
        
        html = response.text
        headers = dict(response.headers)
        
        detected = detect_technologies(target_url, html, headers)
        print(f"[Tech] Detected {len(detected)} technologies")
        return detected
        
    except Exception as e:
        print(f"[Tech] Error: {e}")
        return []
