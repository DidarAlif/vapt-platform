import os
from sqlalchemy import create_engine, text
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

# Lazy engine initialization
_engine = None
_SessionLocal = None

Base = declarative_base()


def get_engine():
    """Get or create database engine (lazy initialization)."""
    global _engine
    if _engine is None:
        _engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    return _engine


def get_session_maker():
    """Get or create session maker (lazy initialization)."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal


def get_db():
    """Dependency to get database session."""
    SessionLocal = get_session_maker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def run_migrations(engine):
    """Run database migrations to add missing columns."""
    migrations = [
        # Add user_id column to scan_records if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'scan_records' AND column_name = 'user_id'
            ) THEN
                ALTER TABLE scan_records ADD COLUMN user_id UUID REFERENCES users(id);
            END IF;
        END $$;
        """,
        # Add scan_mode column if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'scan_records' AND column_name = 'scan_mode'
            ) THEN
                ALTER TABLE scan_records ADD COLUMN scan_mode VARCHAR(50) DEFAULT 'quick';
            END IF;
        END $$;
        """,
        # Add is_verified column to users if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'is_verified'
            ) THEN
                ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;
            END IF;
        END $$;
        """,
        # Add verification_token column to users if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'verification_token'
            ) THEN
                ALTER TABLE users ADD COLUMN verification_token VARCHAR(255);
            END IF;
        END $$;
        """,
        # Add verification_sent_at column to users if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'users' AND column_name = 'verification_sent_at'
            ) THEN
                ALTER TABLE users ADD COLUMN verification_sent_at TIMESTAMP;
            END IF;
        END $$;
        """,
    ]

    
    with engine.connect() as conn:
        for migration in migrations:
            try:
                conn.execute(text(migration))
                conn.commit()
            except Exception as e:
                print(f"Migration warning: {e}")


def init_db():
    """Initialize database tables."""
    try:
        from models import User, ScanRecord  # Import here to avoid circular imports
        engine = get_engine()
        
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)
        print("Database tables initialized successfully")
        
        # Run migrations for existing tables
        run_migrations(engine)
        print("Database migrations completed")
    except Exception as e:
        print(f"Database initialization error: {e}")
