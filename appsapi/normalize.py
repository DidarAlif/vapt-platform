def normalize_nuclei(item: dict):
    severity = item.get("info", {}).get("severity", "info").lower()
    title = item.get("info", {}).get("name", "Unknown")
    matched = item.get("matched-at", "")

    # quick CVSS placeholder mapping (MVP)
    cvss_map = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.0}
    cvss_score = cvss_map.get(severity, 0.0)

    return {
        "title": title,
        "severity": severity,
        "cvss_score": cvss_score,
        "affected_url": matched,
        "tool": "nuclei",
        "description": item.get("info", {}).get("description", ""),
        "reference": item.get("info", {}).get("reference", []),
    }
