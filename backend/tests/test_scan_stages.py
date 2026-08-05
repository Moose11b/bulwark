"""
Concurrent scanner-stage execution.

Stages run in parallel now, so the properties worth pinning down are: they
actually overlap, concurrency stays bounded (every active scanner points at
the same host), and one broken or hung scanner still cannot take the scan
down with it.
"""
import asyncio

import pytest

from app.services import scan_orchestrator as orch
from app.services.scan_orchestrator import _Stage, _run_stages


class FakeRedis:
    """Captures published progress instead of touching Redis."""

    def __init__(self):
        self.messages = []

    async def publish(self, channel, payload):
        import json
        self.messages.append(json.loads(payload))


def _finding(name):
    return {"title": name, "severity": "LOW", "source": name}


async def test_stages_run_concurrently_not_sequentially():
    """Total wall clock should track the slowest stage, not their sum."""
    async def slow(cb, delay=0.3, name="s"):
        await asyncio.sleep(delay)
        return [_finding(name)]

    stages = [
        _Stage(f"stage{i}", 10, lambda cb, i=i: slow(cb, 0.3, f"stage{i}"))
        for i in range(4)
    ]

    r = FakeRedis()
    started = asyncio.get_running_loop().time()
    findings = await _run_stages(r, "scan1", stages, start=10, end=88)
    elapsed = asyncio.get_running_loop().time() - started

    assert len(findings) == 4
    # Sequential would be ~1.2s; concurrent ~0.3s. Generous bound for CI.
    assert elapsed < 0.8, f"stages appear to have run sequentially ({elapsed:.2f}s)"


async def test_concurrency_is_bounded(monkeypatch):
    """More stages than the cap must not all run at once."""
    monkeypatch.setattr(orch.settings, "scan_stage_concurrency", 2, raising=False)

    active = 0
    peak = 0

    async def tracked(cb):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.1)
        active -= 1
        return [_finding("x")]

    stages = [_Stage(f"s{i}", 10, tracked) for i in range(6)]
    await _run_stages(FakeRedis(), "scan1", stages, start=10, end=88)

    assert peak <= 2, f"concurrency cap not enforced (peak {peak})"


async def test_one_failing_stage_does_not_lose_the_others():
    async def ok(cb):
        return [_finding("good")]

    async def boom(cb):
        raise RuntimeError("nmap program was not found in path")

    stages = [
        _Stage("broken", 10, boom),
        _Stage("fine", 10, ok),
    ]
    findings = await _run_stages(FakeRedis(), "scan1", stages, start=10, end=88)

    assert [f["title"] for f in findings] == ["good"]


async def test_hung_stage_is_bounded_by_its_timeout():
    async def hangs(cb):
        await asyncio.sleep(30)

    async def ok(cb):
        return [_finding("good")]

    stages = [
        _Stage("hangs", 1, hangs),   # 1s timeout
        _Stage("fine", 10, ok),
    ]
    started = asyncio.get_running_loop().time()
    findings = await _run_stages(FakeRedis(), "scan1", stages, start=10, end=88)
    elapsed = asyncio.get_running_loop().time() - started

    assert [f["title"] for f in findings] == ["good"]
    assert elapsed < 5, f"hung stage was not cut off ({elapsed:.2f}s)"


async def test_progress_is_monotonic_and_ends_at_the_band_top():
    """Interleaved stages must never send the bar backwards."""
    async def quick(cb, d):
        await asyncio.sleep(d)
        return [_finding("x")]

    # Deliberately finish out of order.
    delays = [0.25, 0.05, 0.15, 0.10]
    stages = [
        _Stage(f"s{i}", 10, lambda cb, d=d: quick(cb, d))
        for i, d in enumerate(delays)
    ]

    r = FakeRedis()
    await _run_stages(r, "scan1", stages, start=10, end=88)

    pcts = [m["progress"] for m in r.messages]
    assert pcts == sorted(pcts), f"progress went backwards: {pcts}"
    assert pcts[-1] == 88, f"final progress should reach the band top, got {pcts[-1]}"


async def test_no_stages_is_a_no_op():
    assert await _run_stages(FakeRedis(), "scan1", [], start=10, end=88) == []
