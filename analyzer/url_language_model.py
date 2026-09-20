from __future__ import annotations

import gzip
import json
import math
import re

from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

from analyzer.scoring_policy import load_scoring_policy


MODEL_PATH = Path(__file__).resolve().parent / "data" / "url_language_model.json.gz"
TOKEN_PATTERN = re.compile(r"[a-z0-9]{3,}")


class URLLanguageModelError(RuntimeError):
    pass


def normalize_url_text(url: str) -> str:
    try:
        parsed = urlsplit(url.strip())
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = f":{parsed.port}" if parsed.port else ""
        value = f"{hostname}{port}{parsed.path or '/'}"
        if parsed.query:
            value += f"?{parsed.query}"
    except (TypeError, ValueError):
        value = str(url).strip().lower()

    return " ".join(unquote(value).lower().split())[:2048]


def _namespaced_ngrams(
    namespace: str,
    value: str,
    ngram_min: int,
    ngram_max: int,
) -> set[str]:
    wrapped = f"^{value}$"
    return {
        f"{namespace}:{wrapped[index : index + size]}"
        for size in range(ngram_min, ngram_max + 1)
        for index in range(max(0, len(wrapped) - size + 1))
    }


def url_features(
    url: str,
    ngram_min: int = 3,
    ngram_max: int = 5,
) -> set[str]:
    normalized = normalize_url_text(url)
    try:
        parsed = urlsplit(url.strip())
        hostname = (parsed.hostname or "").lower().rstrip(".")
        path_query = parsed.path or "/"
        if parsed.query:
            path_query += f"?{parsed.query}"
        path_query = unquote(path_query).lower()[:1536]
    except (TypeError, ValueError):
        hostname = normalized.split("/", 1)[0]
        path_query = normalized[len(hostname) :] or "/"

    features = _namespaced_ngrams(
        "host", hostname, ngram_min, ngram_max
    )
    features.update(
        _namespaced_ngrams("path", path_query, ngram_min, ngram_max)
    )
    if hostname:
        labels = hostname.split(".")
        features.update(
            {
                f"hostname:{hostname}",
                f"tld:{labels[-1]}",
                f"label-count:{min(len(labels), 6)}",
                f"hyphen-count:{min(hostname.count('-'), 6)}",
                f"host-length:{min(len(hostname) // 10, 10)}",
            }
        )
    return features


def raw_model_score(
    url: str,
    weights: dict[str, float],
    ngram_min: int = 3,
    ngram_max: int = 5,
) -> float:
    matched = [
        weights[feature]
        for feature in url_features(url, ngram_min, ngram_max)
        if feature in weights
    ]
    if not matched:
        return 0.0
    return sum(matched) / math.sqrt(len(matched))


@lru_cache(maxsize=1)
def load_model() -> dict:
    try:
        with gzip.open(MODEL_PATH, "rt", encoding="utf-8") as source:
            model = json.load(source)
    except (OSError, ValueError, TypeError) as error:
        raise URLLanguageModelError(
            "The URL language model could not be loaded."
        ) from error

    metadata = model.get("metadata")
    weights = model.get("weights")
    if not isinstance(metadata, dict) or not isinstance(weights, dict):
        raise URLLanguageModelError("The URL language model is invalid.")
    return model


def _probability(raw_score: float, threshold: float, scale: float) -> float:
    value = max(-60.0, min(60.0, (raw_score - threshold) / scale))
    return 1.0 / (1.0 + math.exp(-value))


def _evidence_tokens(
    url: str,
    weights: dict[str, float],
    ngram_min: int,
    ngram_max: int,
) -> list[str]:
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        path_query = unquote(f"{parsed.path}?{parsed.query}").lower()
    except (TypeError, ValueError):
        hostname = str(url).lower()
        path_query = ""

    candidates: list[tuple[float, str]] = []
    for namespace, text in (("host", hostname), ("path", path_query)):
        for token in set(TOKEN_PATTERN.findall(text)):
            features = _namespaced_ngrams(
                namespace, token, ngram_min, ngram_max
            )
            values = [weights[item] for item in features if item in weights]
            if values:
                contribution = sum(values) / math.sqrt(len(values))
                if contribution > 1.0:
                    candidates.append((contribution, token))

    candidates.sort(reverse=True)
    return [token for _, token in candidates[:6]]


def analyze_url_language(url: str) -> dict:
    model = load_model()
    metadata = model["metadata"]
    weights = model["weights"]
    ngram_min = int(metadata.get("ngram_min", 3))
    ngram_max = int(metadata.get("ngram_max", 5))
    threshold = float(metadata["threshold"])
    scale = max(float(metadata["scale"]), 0.001)

    raw_score = raw_model_score(
        url, weights, ngram_min=ngram_min, ngram_max=ngram_max
    )
    probability = _probability(raw_score, threshold, scale)
    candidate_tokens = _evidence_tokens(
        url, weights, ngram_min, ngram_max
    )
    # Ground authoritative domains to avoid false-positive self-brand token matches
    try:
        parsed_host = (urlsplit(url).hostname or "").lower()
        authoritative_roots = (
            "google.com", "google.co.in", "youtube.com", "microsoft.com",
            "apple.com", "amazon.com", "amazon.in", "github.com",
            "gov.in", "nic.in", ".gov"
        )
        is_authoritative = any(
            parsed_host == root or parsed_host.endswith("." + root.lstrip("."))
            for root in authoritative_roots
        )
        if is_authoritative:
            host_tokens = set(TOKEN_PATTERN.findall(parsed_host))
            candidate_tokens = [tok for tok in candidate_tokens if tok not in host_tokens]
            if not candidate_tokens:
                probability = min(probability, 0.40)
    except Exception:
        pass

    lexical_policy = load_scoring_policy()["lexical"]
    elevated = float(lexical_policy["elevated_probability"])
    high = float(lexical_policy["high_probability"])
    evidence_tokens = candidate_tokens if probability >= elevated else []

    if probability >= high:
        status = "High lexical-risk pattern"
    elif probability >= elevated:
        status = "Elevated lexical-risk pattern"
    else:
        status = "No strong lexical-risk pattern"

    return {
        "probability": round(probability, 6),
        "raw_score": round(raw_score, 6),
        "evidence_tokens": evidence_tokens,
        "count": len(evidence_tokens),
        "matches": evidence_tokens,
        "status": status,
        "model_version": metadata["model_version"],
        "complete": True,
    }
