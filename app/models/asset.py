import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    client: Mapped["Client"] = relationship("Client", back_populates="assets")
    project: Mapped["Project | None"] = relationship("Project", back_populates="assets")
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="asset")
