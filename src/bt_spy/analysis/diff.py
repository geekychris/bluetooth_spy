"""Higher-level diffs and aggregations over captured packets.

The DB layer already has `diff_sessions(baseline, candidate)`. This module adds:
- handle activity summaries (frequency, payload-length distribution)
- value variability per handle (constant byte? counter? something high-entropy?)
- candidate field segmentation (look for stable prefixes / variable middles / stable suffixes)
"""

from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class HandleSummary:
    handle: int
    direction: str | None
    count: int
    unique_payloads: int
    sample_payload_hex: str | None
    avg_len: float
    byte_variability: list[float]  # per-position, 0.0 = constant, 1.0 = uniformly random


def handle_summary(conn: sqlite3.Connection, session_id: int) -> list[HandleSummary]:
    """For each (handle, direction) pair, summarise observed payloads.

    `byte_variability[i]` = 1 - (most_common_count_at_pos_i / total). Bytes that
    are always 0x01 score 0.0; bytes that take many distinct values score near 1.0.
    """
    rows = list(conn.execute(
        "SELECT handle, direction, payload FROM packets "
        "WHERE session_id=? AND handle IS NOT NULL AND payload IS NOT NULL",
        (session_id,),
    ))
    grouped: dict[tuple[int, str | None], list[bytes]] = defaultdict(list)
    for r in rows:
        grouped[(r["handle"], r["direction"])].append(bytes(r["payload"]))

    out: list[HandleSummary] = []
    for (handle, direction), payloads in grouped.items():
        unique = len(set(payloads))
        avg_len = sum(len(p) for p in payloads) / len(payloads)
        # Trim to shortest payload for per-byte analysis
        min_len = min(len(p) for p in payloads)
        variability: list[float] = []
        for i in range(min_len):
            c = Counter(p[i] for p in payloads)
            most_common = c.most_common(1)[0][1]
            variability.append(1.0 - most_common / len(payloads))
        out.append(HandleSummary(
            handle=handle,
            direction=direction,
            count=len(payloads),
            unique_payloads=unique,
            sample_payload_hex=payloads[0].hex() if payloads else None,
            avg_len=avg_len,
            byte_variability=variability,
        ))
    out.sort(key=lambda s: (-s.count, s.handle))
    return out


def infer_structure(payloads: list[bytes]) -> list[dict[str, Any]]:
    """Naive segmentation: scan byte-by-byte and group consecutive bytes with
    similar variability into segments. Useful as a starting point Claude can refine.
    """
    if not payloads:
        return []
    min_len = min(len(p) for p in payloads)
    if min_len == 0:
        return []

    counts = [Counter(p[i] for p in payloads) for i in range(min_len)]
    variability = [1.0 - c.most_common(1)[0][1] / len(payloads) for c in counts]

    def label(v: float) -> str:
        if v == 0.0:
            return "constant"
        if v < 0.1:
            return "near_constant"
        if v < 0.5:
            return "low_variance"
        return "high_variance"

    segments: list[dict[str, Any]] = []
    cur_label = label(variability[0])
    cur_start = 0
    for i in range(1, min_len):
        lab = label(variability[i])
        if lab != cur_label:
            segments.append(_segment(cur_start, i, cur_label, payloads, counts))
            cur_start = i
            cur_label = lab
    segments.append(_segment(cur_start, min_len, cur_label, payloads, counts))
    return segments


def _segment(start, end, label, payloads, counts) -> dict[str, Any]:
    seg = {
        "offset": start,
        "length": end - start,
        "kind": label,
    }
    if label in ("constant", "near_constant"):
        seg["likely_value_hex"] = bytes(c.most_common(1)[0][0] for c in counts[start:end]).hex()
    if label == "high_variance":
        seg["distinct_count"] = len({p[start:end] for p in payloads})
    return seg
