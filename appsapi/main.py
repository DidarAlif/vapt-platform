from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List
import uuid
from scanner import run_nuclei_scan, run_header_scan, run_network_scan, run_tech_detection
from normalize import normalize_nuclei
from database import get_db, init_db
from models import ScanRecord, User
from auth import (
    UserCreate, UserLogin, UserResponse, TokenResponse,
    create_user, authenticate_user, get_user_by_email,
    create_access_token, create_refresh_token, verify_token,
    get_current_user, require_user
)

app = FastAPI(title="ReconScience API", description="Advanced Security Reconnaissance Platform")

# CORS middleware - allow frontend domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://reconscience-warns.up.railway.app",
        "https://reconscience.up.railway.app",
        "http://localhost:3000",
        "http://localhost:33490",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:33490",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Initialize database tables on startup."""
    try:
        init_db()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Warning: Database initialization failed: {e}")
        print("App will continue - database operations may fail")


# ============== Health Check ==============
@app.get("/")
def health_check():
    return {"status": "healthy", "service": "reconscience-api", "version": "2.0"}


# ============== Authentication Routes ==============
@app.post("/auth/register", response_model=TokenResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    try:
        existing = get_user_by_email(db, user_data.email)
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        user = create_user(db, user_data)
        
        access_token = create_access_token({"sub": str(user.id), "email": user.email})
        refresh_token = create_refresh_token({"sub": str(user.id), "email": user.email})
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user=UserResponse(
                id=str(user.id),
                email=user.email,
                name=user.name,
                role=user.role,
                created_at=user.created_at
            )
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/auth/login", response_model=TokenResponse)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """Login and get tokens."""
    user = authenticate_user(db, credentials.email, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token({"sub": str(user.id), "email": user.email})
    refresh_token = create_refresh_token({"sub": str(user.id), "email": user.email})
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse(
            id=str(user.id),
            email=user.email,
            name=user.name,
            role=user.role,
            created_at=user.created_at
        )
    )


@app.get("/auth/me", response_model=UserResponse)
def get_me(user: User = Depends(require_user)):
    """Get current user info."""
    return UserResponse(
        id=str(user.id),
        email=user.email,
        name=user.name,
        role=user.role,
        created_at=user.created_at
    )


# ============== Scan Routes ==============
class ScanRequest(BaseModel):
    name: str
    email: str
    target: str
    scan_mode: str = "quick"
    categories: Optional[List[str]] = None


def calculate_risk_score(findings: list) -> int:
    if not findings:
        return 0
    weights = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 1}
    score = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
    return min(100, score)


def analyze_headers(target: str) -> list:
    import requests
    headers_to_check = [
        {"name": "Content-Security-Policy", "risk": "high"},
        {"name": "Strict-Transport-Security", "risk": "high"},
        {"name": "X-Frame-Options", "risk": "medium"},
        {"name": "X-Content-Type-Options", "risk": "low"},
        {"name": "Referrer-Policy", "risk": "medium"},
    ]
    
    results = []
    try:
        response = requests.head(target, timeout=10, allow_redirects=True)
        for h in headers_to_check:
            value = response.headers.get(h["name"])
            results.append({
                "name": h["name"],
                "present": value is not None,
                "value": value,
                "risk": h["risk"],
                "recommendation": f"{'Configured correctly' if value else 'Add ' + h['name'] + ' header'}"
            })
    except:
        for h in headers_to_check:
            results.append({"name": h["name"], "present": False, "value": None, "risk": h["risk"], "recommendation": "Could not check"})
    return results


def get_scan_templates(mode: str, categories: Optional[List[str]] = None) -> str:
    mode_templates = {
        "quick": "technologies,exposures,misconfiguration",
        "full": "cves,vulnerabilities,exposures,misconfiguration,takeovers",
        "network": "network,ssl,dns",
        "custom": ",".join(categories) if categories else "cves,misconfiguration"
    }
    return mode_templates.get(mode, mode_templates["quick"])


@app.post("/scan")
def start_scan(req: ScanRequest, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    try:
        scan_id = str(uuid.uuid4())
        
        # Run the enhanced Nuclei scan with scan mode and categories
        raw_results = run_nuclei_scan(
            target_url=req.target,
            scan_id=scan_id,
            templates="",  # Using tags instead
            scan_mode=req.scan_mode,
            categories=req.categories
        )
        
        # Normalize results
        normalized = [normalize_nuclei(item) for item in raw_results]
        
        formatted_results = [
            {
                "template_id": item.get("template-id", f"finding-{i}"),
                "name": n["title"],
                "severity": n["severity"],
                "matched_at": n["affected_url"],
                "description": n["description"] or "No description available",
                "category": item.get("info", {}).get("tags", ["unknown"])[0] if item.get("info", {}).get("tags") else "unknown",
                "reference": item.get("info", {}).get("reference", [])[:3],  # First 3 references
            }
            for i, (item, n) in enumerate(zip(raw_results, normalized))
        ]
        
        # Run header analysis
        header_result = run_header_scan(req.target)
        headers = header_result.get("results", []) if isinstance(header_result, dict) else analyze_headers(req.target)
        
        # Run tech detection for quick and full scans
        tech_stack = []
        if req.scan_mode in ["quick", "full"]:
            tech_stack = run_tech_detection(req.target, scan_id)
        
        # Calculate risk score
        risk_score = calculate_risk_score(formatted_results)
        
        # Save scan record
        scan_record = ScanRecord(
            user_id=user.id if user else None,
            name=req.name,
            email=req.email,
            target_url=req.target,
            scan_mode=req.scan_mode,
            scan_results={
                "findings": formatted_results,
                "headers": headers,
                "tech_stack": tech_stack,
                "risk_score": risk_score,
                "scan_id": scan_id
            }
        )
        db.add(scan_record)
        db.commit()
        
        return {
            "scan_id": scan_id,
            "findings": formatted_results,
            "headers": headers,
            "tech_stack": tech_stack,
            "risk_score": risk_score,
            "findings_count": len(formatted_results),
            "scan_mode": req.scan_mode
        }
    except Exception as e:
        print(f"Scan error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/scans")
def get_scans(user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Get scan history for authenticated user."""
    scans = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).order_by(ScanRecord.created_at.desc()).all()
    return [
        {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "scan_mode": scan.scan_mode,
            "created_at": scan.created_at.isoformat(),
            "risk_score": scan.scan_results.get("risk_score", 0) if scan.scan_results else 0
        }
        for scan in scans
    ]


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Get specific scan details."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": str(scan.id),
        "target_url": scan.target_url,
        "scan_mode": scan.scan_mode,
        "created_at": scan.created_at.isoformat(),
        "results": scan.scan_results
    }


@app.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Delete a scan."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}


# ============== Report Export Routes ==============
from fastapi.responses import HTMLResponse, JSONResponse
from report import generate_html_report, generate_json_report
from owasp import map_to_owasp, get_owasp_summary


@app.get("/scans/{scan_id}/report/html", response_class=HTMLResponse)
def export_html_report(scan_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Export scan report as HTML."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = {
        "target_url": scan.target_url,
        "scan_mode": scan.scan_mode,
        "created_at": scan.created_at.isoformat(),
        **(scan.scan_results or {})
    }
    
    html_content = generate_html_report(scan_data)
    return HTMLResponse(content=html_content)


@app.get("/scans/{scan_id}/report/json")
def export_json_report(scan_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Export scan report as JSON with OWASP mapping."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = {
        "target_url": scan.target_url,
        "scan_mode": scan.scan_mode,
        "created_at": scan.created_at.isoformat(),
        **(scan.scan_results or {})
    }
    
    return generate_json_report(scan_data)


@app.get("/owasp")
def get_owasp_info():
    """Get OWASP Top 10 2021 categories."""
    from owasp import OWASP_TOP_10
    return OWASP_TOP_10
