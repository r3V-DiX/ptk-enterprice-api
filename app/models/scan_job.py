import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    api_key_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    tools_requested: Mapped[list | None] = mapped_column(JSON, nullable=True)
    tools_run: Mapped[list | None] = mapped_column(JSON, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    client: Mapped["Client"] = relationship("Client", back_populates="scan_jobs")
    project: Mapped["Project | None"] = relationship("Project", back_populates="scan_jobs")
    asset: Mapped["Asset | None"] = relationship("Asset", back_populates="scan_jobs")
    api_key: Mapped["ApiKey | None"] = relationship("ApiKey", back_populates="scan_jobs")
    scan_result: Mapped["ScanResult | None"] = relationship("ScanResult", back_populates="scan_job", uselist=False, cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")
    artifacts: Mapped[list["Artifact"]] = relationship("Artifact", back_populates="scan_job", cascade="all, delete-orphan")
    usage_events: Mapped[list["UsageEvent"]] = relationship("UsageEvent", back_populates="scan_job")
    scan_reports: Mapped[list["ScanReport"]] = relationship("ScanReport", back_populates="scan_job", cascade="all, delete-orphan")
