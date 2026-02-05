import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class ScanRecord(Base):
    """Model to store scan records with user information."""
    __tablename__ = "scan_records"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    target_url = Column(String(2048), nullable=False)
    scan_results = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScanRecord {self.id}: {self.email} -> {self.target_url}>"
