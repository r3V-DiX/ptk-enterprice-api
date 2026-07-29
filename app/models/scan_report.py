import uuid
from datetime import datetime, timezone
from sqlalchemy import String, BigInteger, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ScanReport(Base):
    __tablename__ = "scan_reports"
    __table_args__ = (UniqueConstraint("scan_job_id", "format", name="uq_scan_report_job_format"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    s3_key: Mapped[str] = mapped_column(String(512), nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="scan_reports")
    client: Mapped["Client"] = relationship("Client", back_populates="scan_reports")
