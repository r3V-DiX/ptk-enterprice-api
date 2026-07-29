import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class UsageEvent(Base):
    __tablename__ = "usage_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    api_key_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    client: Mapped["Client"] = relationship("Client", back_populates="usage_events")
    api_key: Mapped["ApiKey | None"] = relationship("ApiKey", back_populates="usage_events")
    scan_job: Mapped["ScanJob | None"] = relationship("ScanJob", back_populates="usage_events")
