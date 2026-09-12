"""Maps attacker/developer rating differences to task difficulty tiers."""

from __future__ import annotations

from dataclasses import dataclass

# Limits of the difficulty scale (agent.md section 6.4)
MIN_TIER = 1
MAX_TIER = 10


@dataclass(frozen=True)
class DifficultyMapping:
    tier: int
    rating_difference: float
    description: str


DIFFICULTY_DESCRIPTIONS = {
    1: "Very Easy - trivial vulnerability patterns",
    2: "Easy - obvious vulnerability patterns",
    3: "Basic - requires basic security awareness",
    4: "Elementary - multiple code paths",
    5: "Intermediate - indirect vulnerability traps",
    6: "Intermediate+ - complex interactions",
    7: "Advanced - multi-step attack chains",
    8: "Advanced+ - subtle vulnerabilities",
    9: "Expert - novel attack vectors",
    10: "Master - adversarial edge cases",
}


def tier_from_rating_difference(diff: float) -> int:
    """Map attacker-minus-developer rating difference to a difficulty tier.

    Tiers map to 100-point Elo difference bands:
        tier 1:  diff < -400
        tier 2: -400 <= diff < -300
        tier 3: -300 <= diff < -200
        tier 4: -200 <= diff < -100
        tier 5: -100 <= diff <= 0
        tier 6:   0 < diff <= 100
        tier 7: 100 < diff <= 200
        tier 8: 200 < diff <= 300
        tier 9: 300 < diff <= 400
        tier 10: diff > 400
    """
    if diff < -400:
        return 1
    elif diff < -300:
        return 2
    elif diff < -200:
        return 3
    elif diff < -100:
        return 4
    elif diff <= 0:
        return 5
    elif diff <= 100:
        return 6
    elif diff <= 200:
        return 7
    elif diff <= 300:
        return 8
    elif diff <= 400:
        return 9
    else:
        return 10


def describe_tier(tier: int) -> str:
    return DIFFICULTY_DESCRIPTIONS.get(tier, "unknown")


def mapping_for(attacker: float, developer: float) -> DifficultyMapping:
    diff = attacker - developer
    tier = tier_from_rating_difference(diff)
    return DifficultyMapping(tier=tier, rating_difference=diff, description=describe_tier(tier))
