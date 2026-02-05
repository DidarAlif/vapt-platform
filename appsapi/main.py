from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import uuid
from scanner import run_nuclei_scan
from normalize import normalize_nuclei
from database import get_db, init_db
from models import ScanRecord

app = FastAPI()

# Add CORS middleware to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Initialize database tables on startup."""
    init_db()


class ScanRequest(BaseModel):
    name: str
    email: str
    target: str


@app.post("/scan")
def start_scan(req: ScanRequest, db: Session = Depends(get_db)):
    scan_id = str(uuid.uuid4())
    raw_results = run_nuclei_scan(req.target, scan_id)
    
    # Normalize results for frontend consumption
    normalized = [normalize_nuclei(item) for item in raw_results]
    
    # Format results for response
    formatted_results = [
        {
            "template_id": item.get("template-id", f"finding-{i}"),
            "name": n["title"],
            "severity": n["severity"],
            "matched_at": n["affected_url"],
            "description": n["description"] or "No description available"
        }
        for i, (item, n) in enumerate(zip(raw_results, normalized))
    ]
    
    # Save scan record to database
    scan_record = ScanRecord(
        name=req.name,
        email=req.email,
        target_url=req.target,
        scan_results=formatted_results
    )
    db.add(scan_record)
    db.commit()
    
    return formatted_results
