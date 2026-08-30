#!/usr/bin/env python3
"""Train the lightweight lexical URL model used by the analyzer.

The training datasets are intentionally not committed. Pass a verified
PhishTank CSV export and a Tranco top-sites ZIP to reproduce the model.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import random
import statistics
import zipfile

from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from analyzer.url_language_model import (
    normalize_url_text,
    raw_model_score,
    url_features,
)


NGRAM_MIN = 3
NGRAM_MAX = 5
DEFAULT_SEED = 20260829

# These paths are training augmentation only. They teach the model that
# ordinary authentication and payment routes also occur on legitimate sites.
BENIGN_PATHS = (
    "/",
    "/login",
    "/signin",
    "/account",
    "/account/reset-password",
    "/auth/callback?state=sample",
    "/checkout/payment",
    "/search?q=security",
    "/support/verify-email",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phishtank", required=True, type=Path)
    parser.add_argument("--tranco", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--phish-limit", type=int, default=70_000)
    parser.add_argument("--benign-domain-limit", type=int, default=40_000)
    parser.add_argument("--max-features", type=int, default=40_000)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--tranco-id", default="unknown")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_hostname(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except (TypeError, ValueError):
        return ""


def split_bucket(url: str) -> int:
    group = extract_hostname(url) or normalize_url_text(url)
    digest = hashlib.sha256(group.encode("utf-8", errors="ignore")).digest()
    return digest[0] % 5


def load_phishing_urls(path: Path, limit: int, seed: int) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            url = (row.get("url") or "").strip()
            normalized = normalize_url_text(url)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            urls.append(url)

    random.Random(seed).shuffle(urls)
    return urls[:limit]


def load_tranco_domains(path: Path, limit: int) -> list[str]:
    domains: list[str] = []
    with zipfile.ZipFile(path) as archive:
        csv_name = archive.namelist()[0]
        with archive.open(csv_name) as binary_source:
            for raw_line in binary_source:
                line = raw_line.decode("utf-8-sig").strip()
                if not line:
                    continue
                _, domain = line.split(",", 1)
                domains.append(domain.strip().lower())
                if len(domains) >= limit:
                    break
    return domains


def build_benign_urls(domains: list[str], seed: int) -> list[str]:
    urls: list[str] = []
    for domain in domains:
        digest = hashlib.sha256(f"{seed}:{domain}".encode()).digest()
        path_offset = digest[0] % len(BENIGN_PATHS)
        for index in range(len(BENIGN_PATHS)):
            path = BENIGN_PATHS[(path_offset + index) % len(BENIGN_PATHS)]
            host = domain
            if index % 3 == 1 and not domain.startswith("www."):
                host = f"www.{domain}"
            urls.append(f"https://{host}{path}")
    return urls


def train_weights(
    samples: list[tuple[str, int]],
    max_features: int,
) -> tuple[dict[str, float], dict[str, int]]:
    class_counts = {0: Counter(), 1: Counter()}
    document_counts = {0: 0, 1: 0}

    for url, label in samples:
        class_counts[label].update(
            url_features(url, NGRAM_MIN, NGRAM_MAX)
        )
        document_counts[label] += 1

    alpha = 1.0
    all_features = set(class_counts[0]) | set(class_counts[1])
    ranked: list[tuple[float, str, float]] = []

    for feature in all_features:
        benign_count = class_counts[0][feature]
        phish_count = class_counts[1][feature]
        total = benign_count + phish_count
        if total < 4:
            continue

        benign_rate = (benign_count + alpha) / (document_counts[0] + 2 * alpha)
        phish_rate = (phish_count + alpha) / (document_counts[1] + 2 * alpha)
        weight = math.log(phish_rate / benign_rate)
        importance = abs(weight) * math.log1p(total)
        ranked.append((importance, feature, weight))

    ranked.sort(reverse=True)
    selected = ranked[:max_features]
    weights = {feature: round(weight, 7) for _, feature, weight in selected}
    return weights, document_counts


def raw_score(url: str, weights: dict[str, float]) -> float:
    return raw_model_score(
        url,
        weights,
        ngram_min=NGRAM_MIN,
        ngram_max=NGRAM_MAX,
    )


def find_threshold(scored: list[tuple[float, int]]) -> float:
    ordered = sorted(scored, reverse=True)
    positives = sum(label for _, label in ordered)
    negatives = len(ordered) - positives
    true_positives = 0
    false_positives = 0
    best_j = float("-inf")
    best_threshold = 0.0

    for index, (score, label) in enumerate(ordered):
        if label:
            true_positives += 1
        else:
            false_positives += 1

        next_score = ordered[index + 1][0] if index + 1 < len(ordered) else None
        if next_score == score:
            continue

        tpr = true_positives / max(positives, 1)
        fpr = false_positives / max(negatives, 1)
        youden_j = tpr - fpr
        if youden_j > best_j:
            best_j = youden_j
            best_threshold = score

    return best_threshold


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def evaluate(
    scored: list[tuple[float, int]],
    threshold: float,
) -> dict[str, float | int]:
    tp = fp = tn = fn = 0
    for score, label in scored:
        predicted = score >= threshold
        if predicted and label:
            tp += 1
        elif predicted:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    specificity = tn / max(tn + fp, 1)
    accuracy = (tp + tn) / max(len(scored), 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {
        "samples": len(scored),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "accuracy": round(accuracy, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "specificity": round(specificity, 6),
        "f1": round(f1, 6),
    }


def main() -> None:
    args = parse_args()
    phishing = load_phishing_urls(args.phishtank, args.phish_limit, args.seed)
    domains = load_tranco_domains(args.tranco, args.benign_domain_limit)
    benign = build_benign_urls(domains, args.seed)

    all_samples = [(url, 1) for url in phishing] + [(url, 0) for url in benign]
    train = [sample for sample in all_samples if split_bucket(sample[0]) != 0]
    validation = [sample for sample in all_samples if split_bucket(sample[0]) == 0]

    validation_weights, document_counts = train_weights(train, args.max_features)
    validation_scores = [
        (raw_score(url, validation_weights), label)
        for url, label in validation
    ]
    threshold = find_threshold(validation_scores)

    benign_scores = [score for score, label in validation_scores if label == 0]
    phishing_scores = [score for score, label in validation_scores if label == 1]
    separation = percentile(phishing_scores, 0.5) - percentile(benign_scores, 0.5)
    scale = max(abs(separation) / 4, statistics.pstdev([score for score, _ in validation_scores]) / 6, 0.1)

    weights, final_document_counts = train_weights(all_samples, args.max_features)

    metadata = {
        "model_version": "2026.08.29-lexical-v2",
        "algorithm": "namespaced-url-feature-log-odds",
        "ngram_min": NGRAM_MIN,
        "ngram_max": NGRAM_MAX,
        "threshold": round(threshold, 8),
        "scale": round(scale, 8),
        "features": len(weights),
        "training_documents": final_document_counts,
        "calibration_documents": document_counts,
        "validation": evaluate(validation_scores, threshold),
        "validation_scope": (
            "Hostname-group holdout metrics for the training procedure; "
            "the packaged model is retrained on all supplied samples."
        ),
        "sources": {
            "phishtank": {
                "url": "https://www.phishtank.net/developer_info.php",
                "sha256": sha256_file(args.phishtank),
                "samples": len(phishing),
            },
            "tranco": {
                "url": "https://tranco-list.eu/",
                "list_id": args.tranco_id,
                "sha256": sha256_file(args.tranco),
                "domains": len(domains),
                "augmented_urls": len(benign),
            },
        },
    }

    payload = {"metadata": metadata, "weights": weights}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    with args.output.open("wb") as binary_target:
        with gzip.GzipFile(
            fileobj=binary_target,
            mode="wb",
            compresslevel=9,
            mtime=0,
        ) as target:
            target.write(encoded)

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(f"model={args.output} bytes={args.output.stat().st_size}")


if __name__ == "__main__":
    main()
