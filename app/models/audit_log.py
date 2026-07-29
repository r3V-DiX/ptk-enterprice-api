import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=True)
    api_key_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True)
    actor: Mapped[str] = mapped_column(String(20), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    client: Mapped["Client | None"] = relationship("Client", back_populates="audit_logs")
    api_key: Mapped["ApiKey | None"] = relationship("ApiKey", back_populates="audit_logs")
