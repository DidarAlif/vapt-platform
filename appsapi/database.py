import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Database URL from environment or default to Docker PostgreSQL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://vapt:vaptpass@localhost:5432/vaptdb"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables."""
    from models import ScanRecord  # Import here to avoid circular imports
    Base.metadata.create_all(bind=engine)
