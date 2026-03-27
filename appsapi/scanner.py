"""
ReconScience Security Scanner - Full Nuclei Power
Comprehensive scanning leveraging Nuclei's 9000+ templates with real-time streaming.
Fixed CLI flags, protocol-type filtering, and redesigned scan profiles.
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
# Each mode uses protocol-type filtering + tags for precise template selection.
# Key insight: `-tags` ONLY matches templates with those exact tags.
# `-type` matches by protocol which catches ALL templates of that type.

NUCLEI_PROFILES = {
    "quick": {
        # Quick: Fast HTTP-based recon — tech fingerprinting, exposed panels, basic misconfigs
        # Uses -type http to match ALL HTTP templates, then filters by tags for recon-relevant ones
        "type": "http",
        "tags": "tech,favicon,waf-detect,fingerprint,misconfig,exposure,panel,detect,login,default-login,wp-plugin,joomla,drupal,apache,nginx,iis",
        "exclude_tags": "dos,fuzz,intrusive,brute-force",
        "severity": "info,low,medium",
        "rate_limit": 150,
        "concurrency": 25,
        "bulk_size": 25,
        "timeout": 8,
        "retries": 1,
        "max_time": 120,  # 2 minutes
        "follow_redirects": True,
        "description": "Quick HTTP recon — tech fingerprinting, exposed panels, basic misconfigs"
    },
    "full": {
        # Full: THE comprehensive scan — run ALL templates across ALL severities.
        # NO tag whitelist — let Nuclei run its full 9000+ template library.
        # Only exclude truly dangerous/noisy categories.
        "type": None,  # No type filter = scan all protocol types
        "tags": None,  # No tag filter = use ALL templates
        "exclude_tags": "dos,fuzz,intrusive",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 100,
        "concurrency": 50,
        "bulk_size": 25,
        "timeout": 15,
        "retries": 2,
        "max_time": 900,  # 15 minutes
        "follow_redirects": True,
        "description": "Comprehensive scan — ALL templates, ALL severities"
    },
    "network": {
        # Network: DNS, SSL/TLS, TCP, and network protocol templates ONLY.
        # Uses -type to select protocol-specific templates that tag filtering would miss.
        "type": "dns,ssl,network,tcp,javascript",
        "tags": None,  # No tag filter within these types = catch everything
        "exclude_tags": "dos,fuzz,intrusive,brute-force",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 50,
        "concurrency": 15,
        "bulk_size": 15,
        "timeout": 20,
        "retries": 2,
        "max_time": 360,  # 6 minutes
        "follow_redirects": False,
        "description": "Network, SSL/TLS, DNS, and TCP protocol analysis"
    },
    "custom": {
        # Custom: User-selected categories via tags, all protocol types
        "type": None,  # No protocol filter for custom
        "severity": "info,low,medium,high,critical",
        "rate_limit": 100,
        "concurrency": 30,
        "bulk_size": 25,
        "timeout": 12,
        "retries": 2,
        "max_time": 600,  # 10 minutes
        "follow_redirects": True,
        "description": "Custom scan with user-selected categories"
    }
}

# Category to Nuclei tags mapping — maps UI categories to ALL relevant template tags
CATEGORY_TAGS = {
    "cves": "cve,cve2024,cve2023,cve2022,cve2021,cve2020,cve2019,cve2018,cve2017,cve2016,cve2015,cve2014,cve2013,cve2012,cve2011,cve2010,vulnerability",
    "misconfig": "misconfig,misconfiguration,default-login,exposed-panel,weak-config,security-misconfiguration,apache,nginx,iis,tomcat",
    "exposures": "exposure,exposed,backup,config,debug,disclosure,sensitive,credentials,secrets,token,api-key,git-config,env-file",
    "takeovers": "takeover,subdomain-takeover,cname-takeover,dns-takeover,cname",
    "ssl": "ssl,tls,certificate,weak-cipher,expired-ssl,heartbleed,poodle,beast,lucky13",
    "xss": "xss,cross-site-scripting,reflected-xss,stored-xss,dom-xss",
    "sqli": "sqli,sql-injection,mysql,mssql,oracle,postgresql,blind-sqli,error-based,time-based",
    "lfi": "lfi,rfi,path-traversal,local-file-inclusion,remote-file-inclusion,file-read",
    "rce": "rce,remote-code-execution,command-injection,code-execution,code-injection,deserialization",
    "ssrf": "ssrf,server-side-request-forgery,url-injection,open-redirect",
    "auth": "auth,authentication,login,default-login,bypass,auth-bypass,idor,broken-access-control",
    "panels": "panel,admin,dashboard,login-panel,admin-panel,cms,wp-admin,phpmyadmin",
    "tech": "tech,technologies,fingerprint,detect,version,framework,cms,waf-detect",
}


def get_nuclei_tags(mode: str, categories: Optional[List[str]] = None) -> Optional[str]:
    """Get Nuclei tags based on scan mode and categories."""
    if mode == "custom" and categories:
        tags = []
        for cat in categories:
            if cat in CATEGORY_TAGS:
                tags.append(CATEGORY_TAGS[cat])
        return ",".join(tags) if tags else None
    
    profile = NUCLEI_PROFILES.get(mode, NUCLEI_PROFILES["quick"])
    return profile.get("tags")


def build_nuclei_command(
    target_url: str,
    output_file: str,
    profile: Dict,
    tags: Optional[str] = None,
    streaming: bool = False,
) -> List[str]:
    """
    Build the correct Nuclei CLI command from a profile.
    Uses proper v3 flags: -c (concurrency), -bs (bulk-size), -rl (rate-limit), etc.
    """
    cmd = [
        "nuclei",
        "-target", target_url,
        "-jsonl",
        "-output", output_file,
        "-severity", profile["severity"],
        "-rl", str(profile["rate_limit"]),
        "-c", str(profile["concurrency"]),
        "-bs", str(profile.get("bulk_size", 25)),
        "-timeout", str(profile["timeout"]),
        "-retries", str(profile["retries"]),
        "-no-color",
        "-ni",  # no-interactsh (short form)
        "-stats",
        "-si", "5" if streaming else "10",  # stats-interval (short form)
    ]

    # Protocol type filtering — the most powerful filter for mode-specific scans
    if profile.get("type"):
        cmd.extend(["-type", profile["type"]])

    # Tag-based filtering (positive selection)
    if tags:
        cmd.extend(["-tags", tags])

    # Tag-based exclusion (negative selection)
    if profile.get("exclude_tags"):
        cmd.extend(["-etags", profile["exclude_tags"]])

    # Follow redirects for HTTP scans
    if profile.get("follow_redirects"):
        cmd.extend(["-fr"])

    # Disable headless browser — faster, avoids chrome dependency
    cmd.extend(["-headless=false"])

    # Use local templates if available
    templates_path = os.getenv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")
    if os.path.exists(templates_path):
        cmd.extend(["-t", templates_path])

    return cmd


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
    
    mode_desc = profile.get("description", scan_mode)
    type_info = f" | Protocol: {profile['type']}" if profile.get("type") else " | All protocols"
    tag_info = f" | Tags: {tags[:50]}..." if tags else " | All templates"
    yield {"type": "status", "message": f"{mode_desc}{type_info}{tag_info}", "progress": 8}
    
    # Build Nuclei command using the centralized builder
    cmd = build_nuclei_command(
        target_url=target_url,
        output_file=str(output_file),
        profile=profile,
        tags=tags,
        streaming=True,
    )
    
    print(f"[Nuclei Stream] Command: {' '.join(cmd[:15])}...")
    yield {"type": "status", "message": "Starting Nuclei scanner...", "progress": 12}
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        findings_count = 0
        current_progress = 12
        max_time = profile["max_time"]
        
        import time
        start_time = time.time()
        
        while process.poll() is None:
            elapsed = time.time() - start_time
            
            # Calculate progress based on elapsed time
            time_progress = min(88, 12 + (elapsed / max_time) * 76)
            
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
                    "message": f"Scanning... ({findings_count} findings, {int(elapsed)}s elapsed)",
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
        
        # Log stderr for debugging if scan returned few/no results
        if process.stderr:
            stderr_text = process.stderr.read()
            if stderr_text:
                # Extract useful stats from stderr
                for line in stderr_text.splitlines():
                    if "templates loaded" in line.lower() or "total" in line.lower():
                        print(f"[Nuclei Stats] {line.strip()}")
        
        yield {"type": "status", "message": f"Nuclei scan complete. {findings_count} findings.", "progress": 95}
        
    except FileNotFoundError:
        yield {"type": "status", "message": "Nuclei binary not found!", "progress": 100}
    except Exception as e:
        yield {"type": "status", "message": f"Scan error: {str(e)}", "progress": 100}


def format_nuclei_finding(raw: Dict, target_url: str) -> Dict:
    """Format a raw Nuclei JSONL finding to our standard structure."""
    info = raw.get("info", {})
    tags = info.get("tags", [])
    
    # Handle tags as both list and comma-separated string
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    
    # Extract classification info (CVE, CWE, CVSS)
    classification = info.get("classification", {})
    
    finding = {
        "template_id": raw.get("template-id", raw.get("templateID", "unknown")),
        "name": info.get("name", raw.get("template-id", "Unknown")),
        "severity": info.get("severity", "info"),
        "type": raw.get("type", "http"),
        "matched_at": raw.get("matched-at", raw.get("host", target_url)),
        "description": info.get("description", "Security finding detected by Nuclei"),
        "category": tags[0] if tags else "nuclei",
        "tags": tags[:10],  # Include up to 10 tags for context
        "reference": info.get("reference", [])[:5] if info.get("reference") else [],
        "matcher_name": raw.get("matcher-name", ""),
        "matcher_status": raw.get("matcher-status", True),
        "extracted_results": raw.get("extracted-results", [])[:5] if raw.get("extracted-results") else [],
        "curl_command": raw.get("curl-command", ""),
    }
    
    # Add classification data if available
    if classification:
        finding["cve_id"] = classification.get("cve-id", [])
        finding["cwe_id"] = classification.get("cwe-id", [])
        finding["cvss_metrics"] = classification.get("cvss-metrics", "")
        finding["cvss_score"] = classification.get("cvss-score", 0)
    
    return finding


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
    print(f"[Nuclei] Profile: {profile['description']}")
    print(f"[Nuclei] Type filter: {profile.get('type', 'ALL')}")
    print(f"[Nuclei] Tags: {tags[:100] if tags else 'ALL (no tag filter)'}")
    print(f"[Nuclei] Severity: {profile['severity']}")
    print(f"[Nuclei] Max time: {profile['max_time']}s")
    
    # Build command using centralized builder
    cmd = build_nuclei_command(
        target_url=target_url,
        output_file=str(output_file),
        profile=profile,
        tags=tags,
        streaming=False,
    )
    
    print(f"[Nuclei] Full command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd, 
            check=False, 
            timeout=profile["max_time"] + 30,  # Buffer beyond max_time
            capture_output=True,
            text=True
        )
        
        if result.stderr:
            # Log template loading stats
            for line in result.stderr.splitlines():
                line_lower = line.lower()
                if any(kw in line_lower for kw in ["templates loaded", "total", "error", "warning"]):
                    print(f"[Nuclei] {line.strip()}")
        
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
    """Network scan using Nuclei's network/SSL/DNS templates."""
    if not NUCLEI_AVAILABLE:
        return []
    
    return run_nuclei_scan_full(target_url, scan_id, "network", None)
