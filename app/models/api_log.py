import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ApiLog(Base):
    __tablename__ = "api_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("clients.id", ondelete="SET NULL"), nullable=True)
    api_key_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True)
    request_id: Mapped[str] = mapped_column(String(32), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    client: Mapped["Client | None"] = relationship("Client")
    api_key: Mapped["ApiKey | None"] = relationship("ApiKey", back_populates="api_logs")
