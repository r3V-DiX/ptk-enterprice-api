import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")
    client: Mapped["Client"] = relationship("Client", back_populates="findings")
