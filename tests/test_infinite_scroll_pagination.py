"""Contract: infinite scroll stops only when the server is exhausted.

The artifact list froze mid-way because the hook used `items.length < total`,
but the server drops rows after counting (junk stripping, filtering, carved-id
dedup), so a page can add fewer than pageSize rows while total stays high. The
fixed hook stops on a short/empty server page, not on a count mismatch.
"""
import re
from pathlib import Path

HOOK = Path(__file__).resolve().parents[1] / "frontend/src/components/forensic/useInfiniteArtifactPage.ts"


def test_hook_does_not_gate_hasmore_on_items_length_vs_total():
    s = HOOK.read_text()
    # The brittle guard must be gone from the code (ignore comment lines).
    code = "\n".join(
        line for line in s.splitlines()
        if not line.strip().startswith("*") and not line.strip().startswith("//")
    )
    assert "const hasMore = items.length < total" not in code
    assert "items.length < total" not in code.replace("const hasMore = !reachedEnd;", "")
    # hasMore is driven by a proven end-of-data flag instead.
    assert "const hasMore = !reachedEnd;" in s


def test_hook_stops_on_short_or_empty_server_page():
    s = HOOK.read_text()
    assert "serverExhausted = returned < ARTIFACT_PAGE_SIZE" in s
    # And guards against a run of all-duplicate/all-filtered pages.
    assert "MAX_EMPTY_STREAK" in s
    assert "emptyStreakRef" in s


def test_hook_recovers_from_transient_fetch_error():
    s = HOOK.read_text()
    # A catch that does NOT set reachedEnd, so scrolling can resume.
    body = s[s.index("} catch"):s.index("} finally")]
    assert "reachedEnd" not in body


def _simulate(page_returns):
    """Mirror the hook's append logic in Python to prove the stop condition.

    page_returns: list of (returned_count, fresh_count) per page.
    Returns the number of pages the hook would actually request.
    """
    PAGE = 20
    MAX_EMPTY = 5
    reached_end = False
    empty_streak = 0
    pages = 0
    for returned, fresh in page_returns:
        if reached_end:
            break
        pages += 1
        server_exhausted = returned < PAGE
        empty_streak = empty_streak + 1 if (fresh == 0 and returned > 0) else 0
        stuck = empty_streak >= MAX_EMPTY
        reached_end = server_exhausted or stuck
    return pages, reached_end


def test_simulation_stops_at_short_page():
    # 3 full pages then a short final page -> 4 requests, then stop.
    pages, end = _simulate([(20, 20), (20, 20), (20, 20), (12, 12)])
    assert (pages, end) == (4, True)


def test_simulation_stops_on_all_duplicate_tail():
    # Full pages that add nothing new (carved dup ids) -> stops after the streak.
    runs = [(20, 20)] + [(20, 0)] * 10
    pages, end = _simulate(runs)
    assert end is True
    assert pages == 1 + 5  # one good page + MAX_EMPTY_STREAK dup pages


def test_simulation_continues_through_short_added_but_full_returned():
    # Server returns full pages that each add some (deduped) rows -> keep going
    # until a short page appears. This is the Picture/All-artifacts case.
    runs = [(20, 14), (20, 9), (20, 20), (7, 7)]
    pages, end = _simulate(runs)
    assert (pages, end) == (4, True)
