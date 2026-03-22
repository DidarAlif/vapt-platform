"""OWASP Top 10 2021 mapping for vulnerability findings."""

OWASP_TOP_10 = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
        "keywords": ["access-control", "privilege", "authorization", "idor", "insecure-direct-object", "path-traversal", "lfi", "rfi"]
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure.",
        "keywords": ["ssl", "tls", "certificate", "crypto", "encryption", "weak-cipher", "cleartext", "https"]
    },
    "A03": {
        "name": "Injection",
        "description": "Injection flaws such as SQL, NoSQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter.",
        "keywords": ["sqli", "sql-injection", "xss", "command-injection", "ldap", "xpath", "ssti", "template-injection", "injection"]
    },
    "A04": {
        "name": "Insecure Design",
        "description": "A category on design and architectural flaws, calling for more threat modeling and secure design patterns.",
        "keywords": ["design", "architecture", "threat-model", "security-control"]
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Missing appropriate security hardening across any part of the application stack.",
        "keywords": ["misconfiguration", "config", "default", "admin-panel", "exposed", "debug", "error-handling", "cors"]
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "keywords": ["cve", "outdated", "component", "library", "framework", "version", "wordpress", "joomla", "drupal"]
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management.",
        "keywords": ["authentication", "session", "credential", "password", "login", "brute", "default-credential"]
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "description": "Relating to code and infrastructure that does not protect against integrity violations.",
        "keywords": ["integrity", "deserialization", "ci-cd", "update", "plugin"]
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Inability to detect, escalate, and respond to active breaches.",
        "keywords": ["logging", "monitoring", "audit", "log"]
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "description": "SSRF flaws occur when a web application is fetching a remote resource without validating the user-supplied URL.",
        "keywords": ["ssrf", "server-side-request", "url-redirect", "open-redirect"]
    }
}


def map_to_owasp(template_id: str, finding_name: str, description: str = "") -> dict:
    """Map a finding to OWASP Top 10 category."""
    text = f"{template_id} {finding_name} {description}".lower()
    
    for code, category in OWASP_TOP_10.items():
        for keyword in category["keywords"]:
            if keyword in text:
                return {
                    "code": code,
                    "name": category["name"],
                    "description": category["description"]
                }
    
    # Default to Security Misconfiguration if no match
    return {
        "code": "A05",
        "name": OWASP_TOP_10["A05"]["name"],
        "description": OWASP_TOP_10["A05"]["description"]
    }


def get_owasp_summary(findings: list) -> dict:
    """Get summary of findings by OWASP category."""
    summary = {}
    for finding in findings:
        mapping = map_to_owasp(
            finding.get("template_id", ""),
            finding.get("name", ""),
            finding.get("description", "")
        )
        code = mapping["code"]
        if code not in summary:
            summary[code] = {
                "name": mapping["name"],
                "count": 0,
                "findings": []
            }
        summary[code]["count"] += 1
        summary[code]["findings"].append(finding)
    
    return summary
