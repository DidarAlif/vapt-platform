"""
Optimized Nuclei Scanner with Full Potential
Includes multiple scan modes, comprehensive templates, and advanced features.
"""
import subprocess
import json
import os
from pathlib import Path
from typing import Optional, List, Dict
from urllib.parse import urlparse

# Scan profiles with optimized template configurations
SCAN_PROFILES = {
    "quick": {
        "templates": [],  # Empty = use tags only
        "tags": "tech,exposure,misconfiguration,osint",
        "exclude_tags": "dos,fuzz",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 150,
        "bulk_size": 25,
        "concurrency": 25,
        "timeout": 10,
        "retries": 2,
        "max_time": 180,  # 3 minutes max
    },
    "full": {
        "templates": [],
        "tags": "cve,vulnerability,exposed,exposure,misconfiguration,misconfig,tech,osint,panel,login,takeover,default-login,file,lfi,xss,sqli,ssrf,rce,redirect,creds-exposure",
        "exclude_tags": "dos,fuzz,intrusive",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 100,
        "bulk_size": 50,
        "concurrency": 50,
        "timeout": 15,
        "retries": 3,
        "max_time": 600,  # 10 minutes max
    },
    "network": {
        "templates": [],
        "tags": "network,ssl,dns,port,service,tls,certificate",
        "exclude_tags": "dos",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 50,
        "bulk_size": 15,
        "concurrency": 15,
        "timeout": 20,
        "retries": 2,
        "max_time": 300,  # 5 minutes max
    },
    "custom": {
        # Will use provided categories
        "templates": [],
        "severity": "info,low,medium,high,critical",
        "rate_limit": 100,
        "bulk_size": 35,
        "concurrency": 35,
        "timeout": 15,
        "retries": 2,
        "max_time": 480,  # 8 minutes max
    }
}

# Category to Nuclei tags mapping
CATEGORY_TAGS = {
    "cves": "cve,cve2023,cve2024,cve2022,cve2021,vulnerability",
    "misconfig": "misconfiguration,misconfig,security-misconfiguration,exposed,default-login",
    "exposures": "exposure,exposed,file,backup,config,debug,disclosure,sensitive",
    "takeovers": "takeover,subdomain-takeover,cname-takeover",
    "ssl": "ssl,tls,certificate,weak-cipher,expired-ssl",
    "xss": "xss,cross-site-scripting,reflected-xss,stored-xss",
    "sqli": "sqli,sql-injection,mysql,mssql,oracle,postgresql",
    "lfi": "lfi,rfi,path-traversal,local-file-inclusion",
    "rce": "rce,remote-code-execution,command-injection",
    "ssrf": "ssrf,server-side-request-forgery,url-injection",
    "auth": "auth,authentication,login,default-login,weak-password,bypass",
    "panels": "panel,admin,dashboard,cms,login-panel,admin-panel",
    "tech": "tech,technologies,fingerprint,detect,version",
    "osint": "osint,whois,dns,cloud,aws,azure,gcp",
}


def get_category_tags(categories: List[str]) -> str:
    """Convert category names to Nuclei tags."""
    tags = []
    for cat in categories:
        if cat in CATEGORY_TAGS:
            tags.append(CATEGORY_TAGS[cat])
    return ",".join(tags) if tags else "cve,misconfiguration,exposure"


def run_nuclei_scan(
    target_url: str, 
    scan_id: str, 
    templates: str = "technologies,exposures",
    scan_mode: str = "quick",
    categories: Optional[List[str]] = None
) -> list:
    """
    Run comprehensive Nuclei scan with optimized settings.
    
    Args:
        target_url: Target URL to scan
        scan_id: Unique scan identifier
        templates: Legacy template string (for backward compatibility)
        scan_mode: Scan mode (quick, full, network, custom)
        categories: Custom categories for custom scan mode
    
    Returns:
        List of findings in JSON format
    """
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "nuclei_results.jsonl"
    
    # Get profile
    profile = SCAN_PROFILES.get(scan_mode, SCAN_PROFILES["quick"])
    
    # Determine tags based on mode
    if scan_mode == "custom" and categories:
        tags = get_category_tags(categories)
    else:
        tags = profile.get("tags", templates)
    
    # Build command with optimized settings
    cmd = [
        "nuclei",
        "-target", target_url,
        "-jsonl",
        "-output", str(output_file),
        "-tags", tags,
        "-severity", profile["severity"],
        "-rate-limit", str(profile["rate_limit"]),
        "-bulk-size", str(profile["bulk_size"]),
        "-concurrency", str(profile["concurrency"]),
        "-timeout", str(profile["timeout"]),
        "-retries", str(profile["retries"]),
        "-stats",
        "-stats-interval", "5",
        "-no-color",
        "-silent",  # Reduce output noise
    ]
    
    # Add exclude tags if specified
    if "exclude_tags" in profile and profile["exclude_tags"]:
        cmd.extend(["-exclude-tags", profile["exclude_tags"]])
    
    # Add template update (use local templates)
    nuclei_templates = os.getenv("NUCLEI_TEMPLATES_PATH")
    if nuclei_templates and os.path.exists(nuclei_templates):
        cmd.extend(["-templates", nuclei_templates])
    
    print(f"[Scanner] Running scan: mode={scan_mode}, tags={tags[:50]}...")
    
    try:
        result = subprocess.run(
            cmd, 
            check=False, 
            timeout=profile["max_time"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0 and result.stderr:
            print(f"[Scanner] Warning: {result.stderr[:200]}")
    except subprocess.TimeoutExpired:
        print(f"[Scanner] Scan timed out after {profile['max_time']}s")
    except FileNotFoundError:
        print("[Scanner] Nuclei not found - returning empty results")
        return []
    except Exception as e:
        print(f"[Scanner] Error: {e}")
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
                findings.append(finding)
            except json.JSONDecodeError:
                pass
    
    print(f"[Scanner] Found {len(findings)} results")
    return findings


def run_header_scan(target_url: str) -> Dict:
    """Run comprehensive security header analysis."""
    import requests
    
    security_headers = {
        "Content-Security-Policy": {
            "risk": "high",
            "description": "Prevents XSS, clickjacking, and other code injection attacks"
        },
        "Strict-Transport-Security": {
            "risk": "high", 
            "description": "Forces HTTPS connections"
        },
        "X-Frame-Options": {
            "risk": "medium",
            "description": "Prevents clickjacking attacks"
        },
        "X-Content-Type-Options": {
            "risk": "medium",
            "description": "Prevents MIME-type sniffing"
        },
        "Referrer-Policy": {
            "risk": "medium",
            "description": "Controls referrer information"
        },
        "Permissions-Policy": {
            "risk": "low",
            "description": "Controls browser features and APIs"
        },
        "X-XSS-Protection": {
            "risk": "low",
            "description": "XSS filter (legacy but still useful)"
        },
        "Cross-Origin-Opener-Policy": {
            "risk": "low",
            "description": "Isolates browsing context"
        },
        "Cross-Origin-Resource-Policy": {
            "risk": "low",
            "description": "Controls cross-origin resource sharing"
        },
    }
    
    results = []
    try:
        response = requests.get(
            target_url, 
            timeout=15, 
            allow_redirects=True,
            headers={"User-Agent": "ReconScience Security Scanner/2.0"}
        )
        
        for header, info in security_headers.items():
            value = response.headers.get(header)
            present = value is not None
            results.append({
                "name": header,
                "present": present,
                "value": value[:100] if value else None,  # Truncate long values
                "risk": info["risk"] if not present else "low",
                "description": info["description"],
                "recommendation": f"Header configured: {value[:50]}..." if present else f"Add {header} header",
            })
            
        # Add server info
        server = response.headers.get("Server", "Unknown")
        results.append({
            "name": "Server",
            "present": True,
            "value": server,
            "risk": "info",
            "description": "Web server identification",
            "recommendation": "Consider removing server banner for security"
        })
        
    except requests.Timeout:
        return {"error": "Request timeout", "results": []}
    except requests.RequestException as e:
        return {"error": str(e), "results": []}
    
    return {"results": results, "total": len(results)}


def run_network_scan(target_url: str, scan_id: str) -> list:
    """Run network reconnaissance scan."""
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "network_results.jsonl"
    
    # Extract domain from URL
    parsed = urlparse(target_url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    
    cmd = [
        "nuclei",
        "-target", domain,
        "-jsonl",
        "-output", str(output_file),
        "-tags", "network,ssl,tls,dns,port,service,certificate,subdomain",
        "-exclude-tags", "dos",
        "-severity", "info,low,medium,high,critical",
        "-rate-limit", "50",
        "-timeout", "20",
        "-retries", "2",
        "-stats",
        "-silent",
    ]

    print(f"[Network Scanner] Scanning domain: {domain}")
    
    try:
        subprocess.run(cmd, check=False, timeout=300, capture_output=True)
    except subprocess.TimeoutExpired:
        print("[Network Scanner] Scan timed out")
    except FileNotFoundError:
        print("[Network Scanner] Nuclei not found")
        return []
    except Exception as e:
        print(f"[Network Scanner] Error: {e}")
        return []

    findings = []
    if output_file.exists():
        for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    
    print(f"[Network Scanner] Found {len(findings)} network findings")
    return findings


def run_tech_detection(target_url: str, scan_id: str) -> list:
    """Run technology detection scan."""
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / "tech_results.jsonl"
    
    cmd = [
        "nuclei",
        "-target", target_url,
        "-jsonl",
        "-output", str(output_file),
        "-tags", "tech,technologies,fingerprint,detect,cms,framework,server",
        "-severity", "info",
        "-rate-limit", "100",
        "-timeout", "10",
        "-silent",
    ]
    
    try:
        subprocess.run(cmd, check=False, timeout=120, capture_output=True)
    except Exception as e:
        print(f"[Tech Scanner] Error: {e}")
        return []
    
    findings = []
    if output_file.exists():
        for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    findings.append({
                        "type": data.get("info", {}).get("tags", ["unknown"])[0] if data.get("info", {}).get("tags") else "technology",
                        "name": data.get("info", {}).get("name", "Unknown"),
                        "version": data.get("matcher-name", ""),
                        "confidence": "high" if data.get("matcher-status") else "medium"
                    })
                except json.JSONDecodeError:
                    pass
    
    return findings
