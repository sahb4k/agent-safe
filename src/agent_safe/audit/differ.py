"""Simple dict differ for before/after state capture."""

from __future__ import annotations

from typing import Any


def compute_state_diff(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Compute a shallow diff between before and after state dicts.

    Returns a dict with keys:
    - added: keys present in after but not before, with their values
    - removed: keys present in before but not after, with their values
    - changed: keys where values differ, with old/new pairs
    - unchanged: list of keys where values are identical
    """
    before_keys = set(before.keys())
    after_keys = set(after.keys())

    added = {k: after[k] for k in sorted(after_keys - before_keys)}
    removed = {k: before[k] for k in sorted(before_keys - after_keys)}
    changed: dict[str, dict[str, Any]] = {}
    unchanged: list[str] = []

    for k in sorted(before_keys & after_keys):
        if before[k] != after[k]:
            changed[k] = {"old": before[k], "new": after[k]}
        else:
            unchanged.append(k)

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }
