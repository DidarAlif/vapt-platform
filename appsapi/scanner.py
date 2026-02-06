"""
ReconScience Security Scanner - Full Nuclei Power
Comprehensive scanning leveraging Nuclei's 9000+ templates.
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
        result = subprocess.run(["nuclei", "-version"], capture_output=True, timeout=10)
        return result.returncode == 0
    except:
        return False

NUCLEI_AVAILABLE = is_nuclei_available()
print(f"[Scanner Init] Nuclei available: {NUCLEI_AVAILABLE}")


# ============== NUCLEI SCAN PROFILES ==============
# Comprehensive profiles using Nuclei's full template library

NUCLEI_PROFILES = {
    "quick": {
        "tags": "technologies,tech,fingerprint,detection,exposed,exposure,login,panel,cms-detect",
        "exclude_tags": "dos,fuzz,intrusive,brute-force",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 150,
        "concurrency": 25,
        "timeout": 10,
        "retries": 2,
        "max_time": 120,  # 2 minutes
        "description": "Quick reconnaissance - technology detection and basic exposures"
    },
    "full": {
        "tags": "cve,cves,vulnerabilities,vulnerability,exposed,exposure,misconfiguration,misconfig,default-login,takeover,xss,sqli,ssrf,lfi,rfi,rce,idor,redirect,injection,auth-bypass,disclosure,token,api,config,backup,panel,login,wp-plugin,joomla,drupal,magento,creds,secrets,credential",
        "exclude_tags": "dos,fuzz,intrusive,brute-force",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 100,
        "concurrency": 50,
        "timeout": 15,
        "retries": 3,
        "max_time": 600,  # 10 minutes
        "description": "Comprehensive vulnerability scan - CVEs, misconfigs, exposures"
    },
    "network": {
        "tags": "network,ssl,tls,certificate,dns,port,service,subdomain,cloud,aws,azure,gcp,cdn,firewall",
        "exclude_tags": "dos",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 50,
        "concurrency": 20,
        "timeout": 20,
        "retries": 2,
        "max_time": 300,  # 5 minutes
        "description": "Network reconnaissance - SSL, DNS, cloud services"
    },
    "custom": {
        "severity": "info,low,medium,high,critical",
        "rate_limit": 100,
        "concurrency": 35,
        "timeout": 15,
        "retries": 2,
        "max_time": 480,
        "description": "Custom scan with selected categories"
    }
}

# Category to Nuclei tags mapping
CATEGORY_TAGS = {
    "cves": "cve,cves,vulnerability,vulnerabilities,cve2024,cve2023,cve2022,cve2021,cve2020",
    "misconfig": "misconfiguration,misconfig,security-misconfiguration,default-login,exposed-panel,weak-config",
    "exposures": "exposure,exposed,backup,config,debug,disclosure,sensitive,credentials,secrets,.git,.env,.svn,.ds_store",
    "takeovers": "takeover,subdomain-takeover,cname-takeover,dns-takeover",
    "ssl": "ssl,tls,certificate,weak-cipher,expired-ssl,ssl-drown,heartbleed",
    "xss": "xss,cross-site-scripting,reflected-xss,stored-xss,dom-xss",
    "sqli": "sqli,sql-injection,mysql,mssql,oracle,postgresql,sqlite",
    "lfi": "lfi,rfi,path-traversal,local-file-inclusion,remote-file-inclusion,file-inclusion",
    "rce": "rce,remote-code-execution,command-injection,code-execution,shell-upload",
    "ssrf": "ssrf,server-side-request-forgery,url-injection,redirect",
    "auth": "auth,authentication,login,default-login,weak-password,bypass,auth-bypass,session",
    "panels": "panel,admin,dashboard,cms,login-panel,admin-panel,webmail,cpanel",
    "tech": "technologies,tech,fingerprint,detect,version,cms-detect,framework",
    "osint": "osint,whois,dns-info,cloud,aws,azure,gcp,google-cloud",
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
    """
    print(f"[Scanner] Starting {scan_mode} scan on {target_url}")
    print(f"[Scanner] Nuclei available: {NUCLEI_AVAILABLE}")
    
    findings = []
    
    if NUCLEI_AVAILABLE:
        # Run full Nuclei scan
        nuclei_findings = run_nuclei_scan_full(target_url, scan_id, scan_mode, categories)
        findings.extend(nuclei_findings)
    else:
        # Fallback to Python-based scanning
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
        "-no-interactsh",  # Disable OOB testing for faster scans
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
                finding = json.loads(line)
                # Format to our standard structure
                findings.append({
                    "template_id": finding.get("template-id", finding.get("templateID", "unknown")),
                    "name": finding.get("info", {}).get("name", finding.get("template-id", "Unknown")),
                    "severity": finding.get("info", {}).get("severity", "info"),
                    "matched_at": finding.get("matched-at", finding.get("host", target_url)),
                    "description": finding.get("info", {}).get("description", "Security finding detected by Nuclei"),
                    "category": finding.get("info", {}).get("tags", ["unknown"])[0] if finding.get("info", {}).get("tags") else "nuclei",
                    "reference": finding.get("info", {}).get("reference", [])[:3] if finding.get("info", {}).get("reference") else [],
                    "matcher_name": finding.get("matcher-name", ""),
                    "extracted_results": finding.get("extracted-results", [])[:5] if finding.get("extracted-results") else [],
                })
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
