from datetime import datetime
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    repo_id: Mapped[int] = mapped_column(index=True)
    branch: Mapped[str] = mapped_column(String(128))
    mode: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(32), default="QUEUED")
    progress: Mapped[int] = mapped_column(default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
