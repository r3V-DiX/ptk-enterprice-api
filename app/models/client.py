import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    company_name: Mapped[str] = mapped_column(String(255), nullable=False)
    contact_email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    tier: Mapped[str] = mapped_column(String(20), nullable=False, default="free")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    webhook_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    webhook_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    webhook_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    webhook_retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    api_keys: Mapped[list["ApiKey"]] = relationship("ApiKey", back_populates="client", cascade="all, delete-orphan")
    projects: Mapped[list["Project"]] = relationship("Project", back_populates="client", cascade="all, delete-orphan")
    assets: Mapped[list["Asset"]] = relationship("Asset", back_populates="client", cascade="all, delete-orphan")
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="client", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="client", cascade="all, delete-orphan")
    usage_events: Mapped[list["UsageEvent"]] = relationship("UsageEvent", back_populates="client", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="client", cascade="all, delete-orphan")
    scan_reports: Mapped[list["ScanReport"]] = relationship("ScanReport", back_populates="client", cascade="all, delete-orphan")
