import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
    scopes: Mapped[list] = mapped_column(JSON, nullable=False, default=lambda: ["scan:write", "scan:read", "usage:read"])
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rate_limit_rpm: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    client: Mapped["Client"] = relationship("Client", back_populates="api_keys")
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="api_key")
    usage_events: Mapped[list["UsageEvent"]] = relationship("UsageEvent", back_populates="api_key")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="api_key")
    api_logs: Mapped[list["ApiLog"]] = relationship("ApiLog", back_populates="api_key")
