"""Tier and feature gating for the commercial dashboard."""

from __future__ import annotations

from pydantic import BaseModel


class TierInfo(BaseModel):
    """Describes what a tier allows."""

    tier: str
    max_users: int
    features: list[str]


TIERS: dict[str, TierInfo] = {
    "free": TierInfo(tier="free", max_users=1, features=[]),
    "team": TierInfo(
        tier="team",
        max_users=10,
        features=["auth", "reports", "users", "clusters", "policies"],
    ),
    "enterprise": TierInfo(
        tier="enterprise",
        max_users=999,
        features=["auth", "reports", "users", "sso", "clusters", "policies"],
    ),
}


def load_tier(tier_name: str) -> TierInfo:
    """Load tier info by name. Defaults to free if unknown."""
    return TIERS.get(tier_name, TIERS["free"])


def has_feature(tier_name: str, feature: str) -> bool:
    """Check if a tier includes a specific feature."""
    return feature in load_tier(tier_name).features
