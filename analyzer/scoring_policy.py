import json

from functools import lru_cache
from pathlib import Path


POLICY_PATH = Path(__file__).resolve().parent / "data" / "scoring_policy.json"


@lru_cache(maxsize=1)
def load_scoring_policy():
    with POLICY_PATH.open("r", encoding="utf-8") as source:
        policy = json.load(source)

    required = {
        "engine_version",
        "policy_version",
        "verdict_bands",
        "lexical",
        "thresholds",
        "weights",
        "category_caps",
        "corroboration_bonus",
        "reputation_floors",
        "minimum_risk",
        "posture",
    }
    if not required.issubset(policy):
        raise RuntimeError("The scoring policy is incomplete.")
    return policy
