"""
Tests for monthly scan quota: enforcement, admin increase, and month-reset behaviour.

Uses SQLite in-memory via real SQLAlchemy session — no mocking of DB layer —
so quota COUNT queries execute exactly as they do in production.
"""
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.api_key import ApiKey
from app.models.client import Client
from app.models.scan_job import ScanJob
from app.services.scan_service import create_scan
from app.services.key_service import create_api_key, update_api_key


# ---------------------------------------------------------------------------
# In-memory SQLite fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    # SQLite doesn't enforce FK by default
    @event.listens_for(engine, "connect")
    def _fk_pragma(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# Fixtures: client + api_key
# ---------------------------------------------------------------------------

@pytest.fixture
def client_row(db):
    c = Client(
        company_name="Test Corp",
        contact_email="test@corp.com",
        tier="pro",
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@pytest.fixture
def api_key_with_quota(db, client_row):
    """API key with scan_quota_per_month=3."""
    key, _ = create_api_key(
        db,
        client_id=client_row.id,
        label="quota-test-key",
        scan_quota_per_month=3,
    )
    return key


@pytest.fixture
def unlimited_key(db, client_row):
    """API key with no quota (unlimited)."""
    key, _ = create_api_key(
        db,
        client_id=client_row.id,
        label="unlimited-key",
        scan_quota_per_month=None,
    )
    return key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan(db, client_id, api_key_id):
    """Create a scan this month and return the ScanJob."""
    job, _ = create_scan(db, client_id=client_id, api_key_id=api_key_id, target="example.com")
    return job


def _backdate_scan(db, scan_job, days_ago: int):
    """Move a scan's created_at into the previous month (for reset tests)."""
    past = datetime.now(timezone.utc) - timedelta(days=days_ago)
    scan_job.created_at = past
    db.commit()


# ---------------------------------------------------------------------------
# Quota enforcement tests
# ---------------------------------------------------------------------------

class TestQuotaEnforcement:
    def test_scan_allowed_under_quota(self, db, client_row, api_key_with_quota):
        """First scan on a key with quota=3 succeeds."""
        job = _scan(db, client_row.id, api_key_with_quota.id)
        assert job.id is not None
        assert job.status == "queued"

    def test_scan_allowed_up_to_limit(self, db, client_row, api_key_with_quota):
        """3 scans on a key with quota=3 all succeed."""
        for _ in range(3):
            job = _scan(db, client_row.id, api_key_with_quota.id)
            assert job.id is not None

    def test_scan_blocked_at_limit(self, db, client_row, api_key_with_quota):
        """4th scan on a key with quota=3 raises SCAN_QUOTA_EXCEEDED."""
        for _ in range(3):
            _scan(db, client_row.id, api_key_with_quota.id)
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)

    def test_unlimited_key_never_blocked(self, db, client_row, unlimited_key):
        """Key with quota=None is never blocked regardless of scan count."""
        for _ in range(10):
            job = _scan(db, client_row.id, unlimited_key.id)
            assert job.id is not None

    def test_quota_counts_failed_scans(self, db, client_row, api_key_with_quota):
        """Failed scans still count toward quota — any row in scan_jobs counts."""
        # Create 2 scans then mark them failed
        j1 = _scan(db, client_row.id, api_key_with_quota.id)
        j2 = _scan(db, client_row.id, api_key_with_quota.id)
        j1.status = "failed"
        j2.status = "failed"
        db.commit()
        # One more is fine (3rd)
        _scan(db, client_row.id, api_key_with_quota.id)
        # 4th is blocked
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)


# ---------------------------------------------------------------------------
# Admin increases quota — scan succeeds after increase
# ---------------------------------------------------------------------------

class TestAdminQuotaIncrease:
    def test_scan_succeeds_after_quota_increase(self, db, client_row, api_key_with_quota):
        """Hit quota=3, admin raises to 5, then 2 more scans succeed."""
        for _ in range(3):
            _scan(db, client_row.id, api_key_with_quota.id)

        # Blocked at 3
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)

        # Admin raises quota to 5
        updated = update_api_key(db, key_id=api_key_with_quota.id, scan_quota_per_month=5)
        assert updated.scan_quota_per_month == 5

        # Now 2 more scans succeed (4th and 5th)
        job4 = _scan(db, client_row.id, api_key_with_quota.id)
        job5 = _scan(db, client_row.id, api_key_with_quota.id)
        assert job4.id is not None
        assert job5.id is not None

        # 6th is blocked again
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)

    def test_admin_sets_unlimited_clears_block(self, db, client_row, api_key_with_quota):
        """Admin sets quota to unlimited (-1 sentinel → NULL) after limit hit."""
        for _ in range(3):
            _scan(db, client_row.id, api_key_with_quota.id)

        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)

        # -1 sentinel → NULL (unlimited)
        updated = update_api_key(db, key_id=api_key_with_quota.id, scan_quota_per_month=-1)
        assert updated.scan_quota_per_month is None

        # Now unlimited — many more scans allowed
        for _ in range(10):
            job = _scan(db, client_row.id, api_key_with_quota.id)
            assert job.id is not None

    def test_admin_reduces_quota_below_current_usage(self, db, client_row, api_key_with_quota):
        """If admin lowers quota below current usage, next scan is immediately blocked."""
        # Use 2 of 3 quota
        _scan(db, client_row.id, api_key_with_quota.id)
        _scan(db, client_row.id, api_key_with_quota.id)

        # Admin reduces quota to 1 (below current count of 2)
        update_api_key(db, key_id=api_key_with_quota.id, scan_quota_per_month=1)

        # Next scan is immediately blocked
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)

    def test_quota_increase_is_reflected_immediately(self, db, client_row, api_key_with_quota):
        """No caching — quota increase takes effect on the very next scan attempt."""
        for _ in range(3):
            _scan(db, client_row.id, api_key_with_quota.id)

        # Blocked
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)

        # Raise by just 1
        update_api_key(db, key_id=api_key_with_quota.id, scan_quota_per_month=4)

        # Immediately works — no server restart needed
        job = _scan(db, client_row.id, api_key_with_quota.id)
        assert job.id is not None


# ---------------------------------------------------------------------------
# Monthly reset — scans from last month don't count
# ---------------------------------------------------------------------------

class TestMonthlyReset:
    def test_scans_from_previous_month_do_not_count(self, db, client_row, api_key_with_quota):
        """Scans backdated to 35+ days ago fall outside the current-month window."""
        # Create 3 scans, backdate them to last month
        for _ in range(3):
            job = _scan(db, client_row.id, api_key_with_quota.id)
            _backdate_scan(db, job, days_ago=35)

        # quota=3, but all 3 are in the previous month — current month count is 0
        # So a new scan this month should succeed
        job_new = _scan(db, client_row.id, api_key_with_quota.id)
        assert job_new.id is not None

    def test_mix_of_old_and_new_scans(self, db, client_row):
        """2 old scans + 1 new scan on a quota=1 key: only the 1 current-month scan counts."""
        # Key with quota=1
        key, _ = create_api_key(db, client_id=client_row.id, scan_quota_per_month=1)

        # 2 scans from last month — backdate them
        for _ in range(2):
            job = _scan(db, client_row.id, key.id)
            _backdate_scan(db, job, days_ago=35)

        # 1 scan this month is fine (count=1 == quota=1, but check is >=)
        # Actually quota check is `scans_this_month >= quota` → 1 >= 1 → blocked on the 1st
        # So 1st current-month scan should succeed (current count is 0 before it's created)
        _scan(db, client_row.id, key.id)

        # 2nd current-month scan is blocked (count is now 1 >= quota 1)
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, key.id)

    def test_quota_fully_resets_at_month_boundary(self, db, client_row, api_key_with_quota):
        """After backdating all current-month scans, the full quota is available again."""
        # Fill up quota this month
        jobs = []
        for _ in range(3):
            jobs.append(_scan(db, client_row.id, api_key_with_quota.id))

        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)

        # Simulate month rollover — backdate all 3 jobs
        for job in jobs:
            _backdate_scan(db, job, days_ago=35)

        # Quota fully available again
        for _ in range(3):
            job = _scan(db, client_row.id, api_key_with_quota.id)
            assert job.id is not None

    def test_current_month_window_uses_utc(self, db, client_row, api_key_with_quota):
        """The window is anchored to the 1st of the current UTC month at 00:00:00."""
        now = datetime.now(timezone.utc)
        # Scan created exactly at month start should count
        job = _scan(db, client_row.id, api_key_with_quota.id)
        job.created_at = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        db.commit()
        # 2 more this month
        _scan(db, client_row.id, api_key_with_quota.id)
        _scan(db, client_row.id, api_key_with_quota.id)
        # 4th blocked
        with pytest.raises(ValueError, match="SCAN_QUOTA_EXCEEDED"):
            _scan(db, client_row.id, api_key_with_quota.id)
