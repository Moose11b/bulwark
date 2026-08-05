"""
Cross-scan finding tracking.

The value of a second scan is knowing what changed, so these pin down the two
halves of that: fingerprints stable enough to recognise the same issue again,
and distinct enough not to merge different ones.
"""
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models import Finding, Scan, ScanStatus, ScanType, Severity
from app.services.fingerprint import finding_fingerprint as fp
from app.services.scan_orchestrator import _persist_findings, _previous_finding_index


# ── Fingerprint identity ─────────────────────────────────────────

def test_same_issue_produces_the_same_fingerprint():
    a = {"source": "header_scanner", "title": "Missing security header: CSP"}
    assert fp(a) == fp(dict(a))


def test_time_relative_wording_does_not_drift():
    """A cert expiring tomorrow is the same finding it was yesterday."""
    base = {"source": "ssl_scanner"}
    day1 = fp({**base, "title": "SSL certificate expiring in 30 days"})
    day2 = fp({**base, "title": "SSL certificate expiring in 29 days"})
    assert day1 == day2, "countdown wording makes a recurring finding look new daily"


def test_meaningful_numbers_stay_distinct():
    """Numbers that are identity, not noise, must not be normalised away."""
    a = fp({"source": "nmap", "title": "Open port 80: HTTP"})
    b = fp({"source": "nmap", "title": "Open port 8080: HTTP"})
    assert a != b, "different ports collapsed into one finding"


def test_cve_outranks_title_wording():
    """The same CVE reworded is still the same finding."""
    a = fp({"source": "nuclei", "cve_id": "CVE-2021-44228", "title": "Log4Shell RCE"})
    b = fp({"source": "nuclei", "cve_id": "CVE-2021-44228", "title": "Apache Log4j2 RCE"})
    assert a == b


def test_same_title_from_different_scanners_is_not_merged():
    a = fp({"source": "nikto", "title": "Directory listing enabled"})
    b = fp({"source": "nuclei", "title": "Directory listing enabled"})
    assert a != b


def test_fingerprint_survives_empty_findings():
    assert fp({}) and fp({"source": "x"})


def test_fingerprint_fits_the_column():
    assert len(fp({"source": "nikto", "title": "x"})) <= 32


# ── Persistence and reconciliation ───────────────────────────────

async def _make_scan(db, org_id, user_id, target="tracked.example.com", asset_id=None,
                     status=ScanStatus.COMPLETED, created_at=None):
    scan = Scan(
        org_id=org_id,
        asset_id=asset_id,
        created_by_id=user_id,
        target=target,
        scan_type=ScanType.HEADERS,
        status=status,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


def _finding(title, source="header_scanner", severity="HIGH"):
    return {"title": title, "source": source, "severity": severity}


@pytest.fixture
async def tracked(test_user_and_org):
    """Two sequential scans of the same target, with cleanup."""
    user_id, org_id = test_user_and_org
    target = f"track-{uuid.uuid4().hex[:8]}.example.com"
    created = []

    async with AsyncSessionLocal() as db:
        first = await _make_scan(
            db, org_id, user_id, target,
            created_at=datetime.utcnow() - timedelta(hours=1),
        )
        created.append(first.id)
        await _persist_findings(db, first, [
            _finding("Missing security header: CSP"),
            _finding("Missing security header: HSTS"),
        ])

    yield {"org_id": org_id, "user_id": user_id, "target": target, "first_id": first.id,
           "scan_ids": created}


async def test_first_scan_marks_everything_new(tracked):
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(Finding).where(Finding.scan_id == tracked["first_id"])
        )).scalars().all()

    assert len(rows) == 2
    assert all(r.is_new for r in rows), "a first scan has no history; all findings are new"
    assert all(r.fingerprint for r in rows)


async def test_recurring_findings_are_not_flagged_new(tracked):
    """Second scan sees the same two issues plus one genuinely new one."""
    async with AsyncSessionLocal() as db:
        second = await _make_scan(db, tracked["org_id"], tracked["user_id"], tracked["target"])
        tracked["scan_ids"].append(second.id)
        await _persist_findings(db, second, [
            _finding("Missing security header: CSP"),     # recurring
            _finding("Missing security header: HSTS"),    # recurring
            _finding("Wildcard CORS policy"),             # new
        ])

        rows = (await db.execute(
            select(Finding).where(Finding.scan_id == second.id)
        )).scalars().all()

    by_title = {r.title: r for r in rows}
    assert by_title["Missing security header: CSP"].is_new is False
    assert by_title["Missing security header: HSTS"].is_new is False
    assert by_title["Wildcard CORS policy"].is_new is True


async def test_first_seen_carries_forward(tracked):
    """The age of an issue must survive re-scanning."""
    async with AsyncSessionLocal() as db:
        original = (await db.execute(
            select(Finding).where(
                Finding.scan_id == tracked["first_id"],
                Finding.title == "Missing security header: CSP",
            )
        )).scalar_one()
        original_first_seen = original.first_seen

        second = await _make_scan(db, tracked["org_id"], tracked["user_id"], tracked["target"])
        tracked["scan_ids"].append(second.id)
        await _persist_findings(db, second, [_finding("Missing security header: CSP")])

        recurring = (await db.execute(
            select(Finding).where(Finding.scan_id == second.id)
        )).scalar_one()

    assert recurring.first_seen == original_first_seen, "issue age reset on re-scan"
    assert recurring.last_seen >= original_first_seen


async def test_failed_scans_are_not_used_as_the_baseline(tracked):
    """Comparing against a failed run would report its gaps as resolved."""
    async with AsyncSessionLocal() as db:
        failed = await _make_scan(
            db, tracked["org_id"], tracked["user_id"], tracked["target"],
            status=ScanStatus.FAILED,
        )
        tracked["scan_ids"].append(failed.id)

        third = await _make_scan(db, tracked["org_id"], tracked["user_id"], tracked["target"])
        tracked["scan_ids"].append(third.id)

        index = await _previous_finding_index(db, third)

    # Should have picked up the completed first scan, not the empty failed one.
    assert len(index) == 2, "baseline should come from the last COMPLETED scan"


async def test_delta_endpoint_reports_new_recurring_and_resolved(client, tracked):
    async with AsyncSessionLocal() as db:
        second = await _make_scan(db, tracked["org_id"], tracked["user_id"], tracked["target"])
        tracked["scan_ids"].append(second.id)
        await _persist_findings(db, second, [
            _finding("Missing security header: CSP"),   # recurring
            _finding("Wildcard CORS policy"),           # new
            # HSTS absent -> resolved
        ])

    r = await client.get(f"/api/scans/{second.id}/delta")
    assert r.status_code == 200
    body = r.json()

    assert body["counts"] == {"new": 1, "recurring": 1, "resolved": 1}
    assert body["new"][0]["title"] == "Wildcard CORS policy"
    assert body["recurring"][0]["title"] == "Missing security header: CSP"
    assert body["resolved"][0]["title"] == "Missing security header: HSTS"
    assert body["is_first_scan"] is False


async def test_delta_on_a_first_scan_says_so(client, tracked):
    r = await client.get(f"/api/scans/{tracked['first_id']}/delta")
    body = r.json()
    assert body["is_first_scan"] is True
    assert body["counts"]["resolved"] == 0
    assert body["counts"]["new"] == 2
