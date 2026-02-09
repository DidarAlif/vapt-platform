"""
ReconScience Security Scanner - Full Nuclei Power
Comprehensive scanning leveraging Nuclei's 9000+ templates with real-time streaming.
"""
import subprocess
import json
import os
import re
import requests
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Generator, AsyncGenerator
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# User agent for requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Check if Nuclei is available
def is_nuclei_available() -> bool:
    try:
        result = subprocess.run(["nuclei", "-version"], capture_output=True, timeout=10)
        return result.returncode == 0
    except:
        return False

NUCLEI_AVAILABLE = is_nuclei_available()
print(f"[Scanner Init] Nuclei available: {NUCLEI_AVAILABLE}")


# ============== NUCLEI SCAN PROFILES ==============
# Each mode has DISTINCT templates for different purposes

NUCLEI_PROFILES = {
    "quick": {
        # Quick: Technology fingerprinting and basic exposures ONLY
        "tags": "tech,favicon,waf-detect,fingerprint",
        "exclude_tags": "cve,vulnerability,dos,fuzz,intrusive,brute-force,sqli,xss,rce,lfi,ssrf",
        "severity": "info,low",
        "rate_limit": 150,
        "concurrency": 25,
        "timeout": 8,
        "retries": 1,
        "max_time": 90,  # 1.5 minutes
        "description": "Quick technology fingerprinting and detection"
    },
    "full": {
        # Full: Comprehensive vulnerability scanning with all CVEs
        "tags": "cve,cve2024,cve2023,cve2022,cve2021,vulnerability,rce,sqli,xss,ssrf,lfi,rfi,auth-bypass,exposure,misconfig,default-login,takeover,injection",
        "exclude_tags": "dos,fuzz,intrusive,brute-force",
        "severity": "low,medium,high,critical",
        "rate_limit": 80,
        "concurrency": 40,
        "timeout": 15,
        "retries": 2,
        "max_time": 600,  # 10 minutes
        "description": "Comprehensive CVE and vulnerability scanning"
    },
    "network": {
        # Network: SSL, DNS, ports, cloud services
        "tags": "ssl,tls,dns,network,cloud,aws,azure,gcp,cdn,certificate,expired-ssl,weak-cipher,subdomain",
        "exclude_tags": "cve,vulnerability,dos,fuzz,web,http",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 50,
        "concurrency": 15,
        "timeout": 20,
        "retries": 2,
        "max_time": 300,  # 5 minutes
        "description": "Network, SSL/TLS, and cloud infrastructure analysis"
    },
    "custom": {
        # Custom: User-selected categories
        "severity": "info,low,medium,high,critical",
        "rate_limit": 100,
        "concurrency": 30,
        "timeout": 12,
        "retries": 2,
        "max_time": 480,  # 8 minutes
        "description": "Custom scan with selected categories"
    }
}

# Category to Nuclei tags mapping - DISTINCT categories
CATEGORY_TAGS = {
    "cves": "cve,cve2024,cve2023,cve2022,cve2021,cve2020,vulnerability",
    "misconfig": "misconfiguration,misconfig,default-login,exposed-panel,weak-config,security-misconfiguration",
    "exposures": "exposure,exposed,backup,config,debug,disclosure,sensitive,.git,.env,.svn,credentials,secrets",
    "takeovers": "takeover,subdomain-takeover,cname-takeover,dns-takeover",
    "ssl": "ssl,tls,certificate,weak-cipher,expired-ssl,heartbleed",
    "xss": "xss,cross-site-scripting,reflected-xss,stored-xss,dom-xss",
    "sqli": "sqli,sql-injection,mysql,mssql,oracle,postgresql",
    "lfi": "lfi,rfi,path-traversal,local-file-inclusion,remote-file-inclusion",
    "rce": "rce,remote-code-execution,command-injection,code-execution",
    "ssrf": "ssrf,server-side-request-forgery,url-injection",
    "auth": "auth,authentication,login,default-login,bypass,auth-bypass",
    "panels": "panel,admin,dashboard,login-panel,admin-panel",
    "tech": "tech,technologies,fingerprint,detect,version,framework",
}


def get_nuclei_tags(mode: str, categories: Optional[List[str]] = None) -> str:
    """Get Nuclei tags based on scan mode and categories."""
    if mode == "custom" and categories:
        tags = []
        for cat in categories:
            if cat in CATEGORY_TAGS:
                tags.append(CATEGORY_TAGS[cat])
        return ",".join(tags) if tags else NUCLEI_PROFILES["full"]["tags"]
    return NUCLEI_PROFILES.get(mode, NUCLEI_PROFILES["quick"]).get("tags", "")


# ============== STREAMING NUCLEI SCAN ==============

def stream_nuclei_scan(
    target_url: str, 
    scan_id: str, 
    scan_mode: str = "quick",
    categories: Optional[List[str]] = None
) -> Generator[Dict, None, None]:
    """
    Generator that streams Nuclei scan progress and findings in real-time.
    Yields status updates and findings as they come in.
    """
    print(f"[Scanner] Starting streaming {scan_mode} scan on {target_url}")
    
    if not NUCLEI_AVAILABLE:
        # Fallback to Python-based scanning
        yield {"type": "status", "message": "Nuclei not available, using Python-based scanning", "progress": 10}
        for finding in run_python_security_checks(target_url):
            yield {"type": "finding", "data": finding}
        yield {"type": "status", "message": "Python-based scan complete", "progress": 100}
        return
    
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "nuclei_results.jsonl"
    
    profile = NUCLEI_PROFILES.get(scan_mode, NUCLEI_PROFILES["quick"])
    tags = get_nuclei_tags(scan_mode, categories)
    
    yield {"type": "status", "message": f"Initializing {scan_mode} scan...", "progress": 5}
    yield {"type": "status", "message": f"Loading templates: {tags[:60]}...", "progress": 10}
    
    # Build Nuclei command
    cmd = [
        "nuclei",
        "-target", target_url,
        "-jsonl",
        "-output", str(output_file),
        "-severity", profile["severity"],
        "-rate-limit", str(profile["rate_limit"]),
        "-concurrency", str(profile["concurrency"]), 
        "-timeout", str(profile["timeout"]),
        "-retries", str(profile["retries"]),
        "-stats",
        "-stats-interval", "5",
        "-no-color",
        "-no-interactsh",
    ]
    
    if tags:
        cmd.extend(["-tags", tags])
    
    if "exclude_tags" in profile and profile["exclude_tags"]:
        cmd.extend(["-exclude-tags", profile["exclude_tags"]])
    
    templates_path = os.getenv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")
    if os.path.exists(templates_path):
        cmd.extend(["-templates", templates_path])
    
    yield {"type": "status", "message": "Starting Nuclei scanner...", "progress": 15}
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        findings_count = 0
        current_progress = 15
        max_time = profile["max_time"]
        
        # Read stderr for stats (Nuclei outputs stats to stderr)
        import select
        import time
        start_time = time.time()
        
        while process.poll() is None:
            elapsed = time.time() - start_time
            
            # Calculate progress based on elapsed time
            time_progress = min(85, 15 + (elapsed / max_time) * 70)
            
            # Check if there are new findings in the output file
            if output_file.exists():
                try:
                    content = output_file.read_text(encoding="utf-8", errors="ignore")
                    lines = [l for l in content.splitlines() if l.strip()]
                    
                    # Yield any new findings
                    while findings_count < len(lines):
                        try:
                            finding_raw = json.loads(lines[findings_count])
                            finding = format_nuclei_finding(finding_raw, target_url)
                            yield {"type": "finding", "data": finding}
                            findings_count += 1
                        except json.JSONDecodeError:
                            findings_count += 1
                except:
                    pass
            
            # Yield progress update
            if int(time_progress) > int(current_progress):
                current_progress = time_progress
                yield {
                    "type": "status", 
                    "message": f"Scanning... ({findings_count} findings so far)",
                    "progress": int(current_progress)
                }
            
            time.sleep(1)
            
            # Check timeout
            if elapsed > max_time:
                process.terminate()
                yield {"type": "status", "message": f"Scan timed out after {max_time}s", "progress": 90}
                break
        
        # Get any remaining findings
        if output_file.exists():
            content = output_file.read_text(encoding="utf-8", errors="ignore")
            lines = [l for l in content.splitlines() if l.strip()]
            while findings_count < len(lines):
                try:
                    finding_raw = json.loads(lines[findings_count])
                    finding = format_nuclei_finding(finding_raw, target_url)
                    yield {"type": "finding", "data": finding}
                    findings_count += 1
                except:
                    findings_count += 1
        
        yield {"type": "status", "message": f"Nuclei scan complete. {findings_count} findings.", "progress": 95}
        
    except FileNotFoundError:
        yield {"type": "status", "message": "Nuclei binary not found!", "progress": 100}
    except Exception as e:
        yield {"type": "status", "message": f"Scan error: {str(e)}", "progress": 100}


def format_nuclei_finding(raw: Dict, target_url: str) -> Dict:
    """Format a raw Nuclei finding to our standard structure."""
    info = raw.get("info", {})
    tags = info.get("tags", [])
    
    return {
        "template_id": raw.get("template-id", raw.get("templateID", "unknown")),
        "name": info.get("name", raw.get("template-id", "Unknown")),
        "severity": info.get("severity", "info"),
        "matched_at": raw.get("matched-at", raw.get("host", target_url)),
        "description": info.get("description", "Security finding detected by Nuclei"),
        "category": tags[0] if tags else "nuclei",
        "reference": info.get("reference", [])[:3] if info.get("reference") else [],
        "matcher_name": raw.get("matcher-name", ""),
        "extracted_results": raw.get("extracted-results", [])[:5] if raw.get("extracted-results") else [],
    }


# ============== MAIN NUCLEI SCAN FUNCTION ==============

def run_nuclei_scan(
    target_url: str, 
    scan_id: str, 
    templates: str = "",
    scan_mode: str = "quick",
    categories: Optional[List[str]] = None
) -> List[Dict]:
    """
    Run comprehensive Nuclei scan with full template library.
    Returns all findings at once (non-streaming version).
    """
    print(f"[Scanner] Starting {scan_mode} scan on {target_url}")
    print(f"[Scanner] Nuclei available: {NUCLEI_AVAILABLE}")
    
    findings = []
    
    if NUCLEI_AVAILABLE:
        nuclei_findings = run_nuclei_scan_full(target_url, scan_id, scan_mode, categories)
        findings.extend(nuclei_findings)
    else:
        print("[Scanner] Nuclei not available, using Python-based scanning")
        python_findings = run_python_security_checks(target_url)
        findings.extend(python_findings)
    
    print(f"[Scanner] Total findings: {len(findings)}")
    return findings


def run_nuclei_scan_full(
    target_url: str, 
    scan_id: str, 
    scan_mode: str,
    categories: Optional[List[str]] = None
) -> List[Dict]:
    """Run Nuclei with full power using comprehensive options."""
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "nuclei_results.jsonl"
    
    profile = NUCLEI_PROFILES.get(scan_mode, NUCLEI_PROFILES["quick"])
    tags = get_nuclei_tags(scan_mode, categories)
    
    print(f"[Nuclei] Mode: {scan_mode}")
    print(f"[Nuclei] Tags: {tags[:100]}...")
    print(f"[Nuclei] Severity: {profile['severity']}")
    print(f"[Nuclei] Max time: {profile['max_time']}s")
    
    # Build comprehensive Nuclei command
    cmd = [
        "nuclei",
        "-target", target_url,
        "-jsonl",
        "-output", str(output_file),
        "-severity", profile["severity"],
        "-rate-limit", str(profile["rate_limit"]),
        "-concurrency", str(profile["concurrency"]), 
        "-timeout", str(profile["timeout"]),
        "-retries", str(profile["retries"]),
        "-stats",
        "-stats-interval", "10",
        "-no-color",
        "-silent",
        "-no-interactsh",
    ]
    
    # Add tags
    if tags:
        cmd.extend(["-tags", tags])
    
    # Add exclude tags if specified
    if "exclude_tags" in profile and profile["exclude_tags"]:
        cmd.extend(["-exclude-tags", profile["exclude_tags"]])
    
    # Use local templates if available
    templates_path = os.getenv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")
    if os.path.exists(templates_path):
        cmd.extend(["-templates", templates_path])
        print(f"[Nuclei] Using templates from: {templates_path}")
    
    print(f"[Nuclei] Running command...")
    
    try:
        result = subprocess.run(
            cmd, 
            check=False, 
            timeout=profile["max_time"],
            capture_output=True,
            text=True
        )
        
        if result.stderr:
            if "error" in result.stderr.lower():
                print(f"[Nuclei] Stderr: {result.stderr[:500]}")
        
        print(f"[Nuclei] Scan completed with return code: {result.returncode}")
        
    except subprocess.TimeoutExpired:
        print(f"[Nuclei] Scan timed out after {profile['max_time']}s (this is normal for large scans)")
    except FileNotFoundError:
        print("[Nuclei] Binary not found!")
        return []
    except Exception as e:
        print(f"[Nuclei] Error: {e}")
        return []

    # Parse results
    findings = []
    if output_file.exists():
        content = output_file.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                finding_raw = json.loads(line)
                findings.append(format_nuclei_finding(finding_raw, target_url))
            except json.JSONDecodeError:
                pass
    
    print(f"[Nuclei] Parsed {len(findings)} findings")
    return findings


# ============== PYTHON-BASED FALLBACK SCANNING ==============

SECURITY_CHECKS = [
    {"id": "exposed-git", "name": "Exposed .git directory", "path": "/.git/config", "severity": "high",
     "check": lambda r: "[core]" in r.text or "repositoryformatversion" in r.text,
     "description": "Git configuration file exposed, may leak source code"},
    {"id": "exposed-env", "name": "Exposed .env file", "path": "/.env", "severity": "critical",
     "check": lambda r: "=" in r.text and len(r.text) < 10000 and r.status_code == 200,
     "description": "Environment file exposed, may contain credentials"},
    {"id": "exposed-wp-config", "name": "WordPress Config Backup", "path": "/wp-config.php.bak", "severity": "critical",
     "check": lambda r: "DB_PASSWORD" in r.text, "description": "WordPress configuration backup exposed"},
    {"id": "exposed-debug", "name": "Debug Mode Enabled", "path": "/", "severity": "medium",
     "check": lambda r: "Traceback" in r.text or "stack trace" in r.text.lower(),
     "description": "Debug mode appears to be enabled"},
    {"id": "exposed-phpinfo", "name": "PHPInfo Exposed", "path": "/phpinfo.php", "severity": "medium",
     "check": lambda r: "PHP Version" in r.text and "phpinfo()" in r.text,
     "description": "PHPInfo page exposed, reveals server configuration"},
    {"id": "exposed-backup", "name": "Backup File Found", "path": "/backup.zip", "severity": "high",
     "check": lambda r: r.status_code == 200 and len(r.content) > 100,
     "description": "Backup file publicly accessible"},
    {"id": "exposed-sql", "name": "SQL Dump Exposed", "path": "/database.sql", "severity": "critical",
     "check": lambda r: "CREATE TABLE" in r.text or "INSERT INTO" in r.text,
     "description": "Database dump file exposed"},
    {"id": "exposed-ds-store", "name": ".DS_Store Exposed", "path": "/.DS_Store", "severity": "low",
     "check": lambda r: r.status_code == 200 and b'\x00\x00\x00\x01Bud1' in r.content[:12],
     "description": "macOS .DS_Store file exposed, reveals directory structure"},
    {"id": "exposed-svn", "name": ".svn Exposed", "path": "/.svn/entries", "severity": "high",
     "check": lambda r: r.status_code == 200 and ("dir" in r.text.lower() or "svn" in r.text.lower()),
     "description": "SVN repository metadata exposed"},
]


def run_python_security_checks(url: str) -> List[Dict]:
    """Fallback Python-based security checks when Nuclei isn't available."""
    findings = []
    
    for check in SECURITY_CHECKS:
        try:
            full_url = url.rstrip("/") + check["path"]
            response = requests.get(full_url, timeout=10, headers={"User-Agent": USER_AGENT}, allow_redirects=False, verify=False)
            
            if check["check"](response):
                findings.append({
                    "template_id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "matched_at": full_url,
                    "description": check["description"],
                    "category": "exposure"
                })
        except:
            pass
    
    return findings


# ============== HEADER ANALYSIS ==============

SECURITY_HEADERS = {
    "Content-Security-Policy": {"risk": "high", "description": "Prevents XSS and code injection"},
    "Strict-Transport-Security": {"risk": "high", "description": "Forces HTTPS connections"},
    "X-Frame-Options": {"risk": "medium", "description": "Prevents clickjacking"},
    "X-Content-Type-Options": {"risk": "medium", "description": "Prevents MIME sniffing"},
    "Referrer-Policy": {"risk": "medium", "description": "Controls referrer information"},
    "Permissions-Policy": {"risk": "low", "description": "Controls browser features"},
    "X-XSS-Protection": {"risk": "low", "description": "Legacy XSS filter"},
    "Cross-Origin-Opener-Policy": {"risk": "low", "description": "Isolates browsing context"},
    "Cross-Origin-Resource-Policy": {"risk": "low", "description": "Controls resource sharing"},
}


def run_header_scan(target_url: str) -> Dict:
    """Analyze security headers."""
    results = []
    
    try:
        response = requests.get(target_url, timeout=15, headers={"User-Agent": USER_AGENT}, allow_redirects=True, verify=False)
        
        for header_name, config in SECURITY_HEADERS.items():
            value = response.headers.get(header_name)
            present = value is not None
            results.append({
                "name": header_name,
                "present": present,
                "value": value[:100] if value else None,
                "risk": config["risk"] if not present else "low",
                "description": config["description"],
                "recommendation": f"✓ {value[:50]}..." if present else f"Add {header_name} header"
            })
        
        server = response.headers.get("Server", "")
        if server:
            results.append({
                "name": "Server", "present": True, "value": server,
                "risk": "info", "description": "Web server identification",
                "recommendation": "Consider removing server banner"
            })
            
    except Exception as e:
        print(f"[Headers] Error: {e}")
        for header_name, config in SECURITY_HEADERS.items():
            results.append({
                "name": header_name, "present": False, "value": None,
                "risk": "unknown", "description": config["description"],
                "recommendation": "Could not check - connection error"
            })
    
    return {"results": results, "total": len(results)}


# ============== TECHNOLOGY DETECTION ==============

TECH_SIGNATURES = {
    "WordPress": {"patterns": [r"wp-content", r"wp-includes", r"/wp-json/"], "type": "CMS"},
    "Joomla": {"patterns": [r"/media/jui/", r"Joomla!"], "type": "CMS"},
    "Drupal": {"patterns": [r"Drupal", r"/sites/default/"], "type": "CMS"},
    "React": {"patterns": [r"__REACT", r"data-reactroot"], "type": "Frontend"},
    "Vue.js": {"patterns": [r"__VUE__", r"data-v-"], "type": "Frontend"},
    "Angular": {"patterns": [r"ng-version", r"ng-app"], "type": "Frontend"},
    "Next.js": {"patterns": [r"__NEXT_DATA__", r"_next/static"], "type": "Frontend"},
    "jQuery": {"patterns": [r"jquery"], "type": "JavaScript"},
    "Bootstrap": {"patterns": [r"bootstrap"], "type": "CSS Framework"},
    "Tailwind": {"patterns": [r"tailwindcss"], "type": "CSS Framework"},
    "PHP": {"headers": {"X-Powered-By": "PHP"}, "type": "Backend"},
    "ASP.NET": {"headers": {"X-Powered-By": "ASP.NET"}, "type": "Backend"},
    "Express": {"headers": {"X-Powered-By": "Express"}, "type": "Backend"},
    "Nginx": {"headers": {"Server": "nginx"}, "type": "Web Server"},
    "Apache": {"headers": {"Server": "Apache"}, "type": "Web Server"},
    "Cloudflare": {"headers": {"Server": "cloudflare"}, "type": "CDN"},
    "LiteSpeed": {"headers": {"Server": "LiteSpeed"}, "type": "Web Server"},
    "IIS": {"headers": {"Server": "Microsoft-IIS"}, "type": "Web Server"},
}


def run_tech_detection(target_url: str, scan_id: str) -> List[Dict]:
    """Detect technologies used by the target."""
    print(f"[Tech] Detecting technologies for {target_url}")
    detected = []
    
    try:
        response = requests.get(target_url, timeout=15, headers={"User-Agent": USER_AGENT}, allow_redirects=True, verify=False)
        html = response.text
        headers = dict(response.headers)
        
        for tech_name, config in TECH_SIGNATURES.items():
            found = False
            version = None
            
            # Check patterns
            if "patterns" in config:
                for pattern in config["patterns"]:
                    if re.search(pattern, html, re.IGNORECASE):
                        found = True
                        break
            
            # Check headers
            if "headers" in config:
                for h_name, h_value in config["headers"].items():
                    actual = headers.get(h_name, "")
                    if h_value.lower() in actual.lower():
                        found = True
                        version_match = re.search(r"[\d.]+", actual)
                        if version_match:
                            version = version_match.group()
            
            if found:
                detected.append({"name": tech_name, "type": config["type"], "version": version, "confidence": "high"})
        
        print(f"[Tech] Detected {len(detected)} technologies")
        
    except Exception as e:
        print(f"[Tech] Error: {e}")
    
    return detected


def run_network_scan(target_url: str, scan_id: str) -> List[Dict]:
    """Network scan using Nuclei's network templates."""
    if not NUCLEI_AVAILABLE:
        return []
    
    return run_nuclei_scan_full(target_url, scan_id, "network", None)
