from datetime import datetime
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Patch(Base):
    __tablename__ = "patches"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    vuln_id: Mapped[str] = mapped_column(String(64), index=True)
    original_code: Mapped[str] = mapped_column(String)
    patched_code: Mapped[str] = mapped_column(String)
    explanation: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column()
    status: Mapped[str] = mapped_column(String(32), default="GENERATED")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
