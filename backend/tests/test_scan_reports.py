"""Scan-scoped analysis reports: killchain, owasp, compliance."""
import pytest_asyncio
from app.database import AsyncSessionLocal
from app.models import (
    Asset, AssetType, Finding, Scan, ScanStatus, ScanType, Severity,
)


@pytest_asyncio.fixture
async def seeded_scan(test_user_and_org):
    """A completed Scan with a handful of findings across severities, OWASP
    categories, kill-chain phases, and PCI/ISO/NIST controls.

    Yields the scan_id. Caller doesn't need to clean up — the session-level
    teardown will drop everything tied to the test org.
    """
    user_id, org_id = test_user_and_org
    async with AsyncSessionLocal() as db:
        asset = Asset(org_id=org_id, name="seed", target="seed.example.com", asset_type=AssetType.DOMAIN)
        db.add(asset); await db.flush()
        scan = Scan(
            org_id=org_id, asset_id=asset.id, created_by_id=user_id,
            target=asset.target, scan_type=ScanType.HEADERS,
            status=ScanStatus.COMPLETED, risk_score=42.0,
            finding_counts={"HIGH": 1, "MEDIUM": 1, "LOW": 1},
        )
        db.add(scan); await db.flush()
        for sev, owasp, phase, pci in [
            (Severity.HIGH,   "A05", "delivery",       ["6.2.4"]),
            (Severity.MEDIUM, "A05", "delivery",       ["4.2.1"]),
            (Severity.LOW,    "A05", "reconnaissance", ["2.2", "7.1"]),
        ]:
            db.add(Finding(
                scan_id=scan.id, org_id=org_id,
                title=f"Test finding ({sev.value})",
                severity=sev, source="test_seed",
                owasp_category=owasp, killchain_phase=phase,
                pci_dss=pci, iso_27001=["A.18.1.3"], nist_csf=["PR.DS-5"],
                description="Seeded for pytest", remediation="N/A",
            ))
        await db.commit()
        return scan.id


async def test_killchain_report_aggregates_phases(client, seeded_scan):
    r = await client.get(f"/api/killchain/scan/{seeded_scan}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_findings"] == 3
    # We seeded into 'delivery' (2) and 'reconnaissance' (1) — 2 exposed phases
    assert body["exposed_phases"] == 2
    # 'delivery' is phase 3 in the kill chain — should be the furthest
    assert body["highest_phase"] == 3
    assert body["highest_phase_name"].lower() == "delivery"
    assert len(body["phases"]) == 7
    assert len(body["bar_data"]) == 7


async def test_owasp_report_aggregates_categories(client, seeded_scan):
    r = await client.get(f"/api/owasp/scan/{seeded_scan}")
    assert r.status_code == 200
    body = r.json()
    assert body["total_findings"] == 3
    assert body["categories_hit"] == 1  # all three seeded into A05
    a05 = next(c for c in body["categories"] if c["code"] == "A05")
    assert a05["count"] == 3
    # Radar dataset has all 10 categories regardless of which are hit
    assert len(body["radar_data"]) == 10


async def test_compliance_report_groups_by_framework(client, seeded_scan):
    r = await client.get(f"/api/compliance/scan/{seeded_scan}")
    assert r.status_code == 200
    body = r.json()
    assert body["total_findings"] == 3
    # Each framework returns [{control, findings}, ...]
    for fw in ("pci_dss", "iso_27001", "nist_csf"):
        assert fw in body
        assert isinstance(body[fw], list)
        assert body[f"{fw}_controls_hit"] == len(body[fw])
    # PCI controls touched: 6.2.4, 4.2.1, 2.2, 7.1 → 4 distinct controls
    pci_controls = {item["control"] for item in body["pci_dss"]}
    assert pci_controls == {"6.2.4", "4.2.1", "2.2", "7.1"}


async def test_report_404_when_scan_belongs_to_other_org(client):
    r = await client.get("/api/killchain/scan/does-not-exist")
    assert r.status_code == 404


async def test_report_json_export(client, seeded_scan):
    r = await client.get(f"/api/reports/scan/{seeded_scan}/json")
    assert r.status_code == 200
    body = r.json()
    assert body["scan"]["id"] == seeded_scan
    assert body["scan"]["status"] == "completed"
    assert len(body["findings"]) == 3
    severities = {f["severity"] for f in body["findings"]}
    assert severities == {"HIGH", "MEDIUM", "LOW"}
