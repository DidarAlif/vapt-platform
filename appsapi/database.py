import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Database URL from environment (check both cases) or default to Docker PostgreSQL
DATABASE_URL = (
    os.getenv("DATABASE_URL") or 
    os.getenv("database_url") or
    "postgresql://vapt:vaptpass@localhost:5432/vaptdb"
)

# Railway uses postgres:// but SQLAlchemy needs postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

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
