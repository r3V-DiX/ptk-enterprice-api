import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, unique=True)
    result_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="scan_result")
