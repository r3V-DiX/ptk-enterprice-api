import uuid
from datetime import datetime, timezone
from sqlalchemy import String, BigInteger, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)
    s3_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="artifacts")
