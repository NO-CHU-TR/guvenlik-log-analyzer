"""
Database Models
Define security event and report tables.
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()


class SecurityEvent(Base):
    """Security event record."""
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, nullable=False)
    aciklama = Column(String(255), nullable=False)
    skor = Column(Float, nullable=False)
    seviye = Column(String(20), nullable=False)
    kullanici = Column(String(100))
    kaynak_ip = Column(String(50))
    zaman = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    
    def __repr__(self):
        return f"<SecurityEvent {self.event_id} - {self.seviye}>"


class ScanResult(Base):
    """Scan result summary."""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True)
    scan_date = Column(DateTime, default=datetime.now)
    total_events = Column(Integer)
    kritik_count = Column(Integer, default=0)
    yuksek_count = Column(Integer, default=0)
    orta_count = Column(Integer, default=0)
    dusuk_count = Column(Integer, default=0)
    avg_score = Column(Float)
    
    def __repr__(self):
        return f"<ScanResult {self.scan_date} - {self.total_events} events>"


def init_db(db_path: str = "guvenlik.db"):
    """Initialize database."""
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return engine


def get_session(engine):
    """Get database session."""
    Session = sessionmaker(bind=engine)
    return Session()