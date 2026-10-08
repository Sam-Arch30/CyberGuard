"""
Novelty Engine Structured Observability & Metrics (Section 22).

Tracks evaluation volumes, classification ratios, emerging pattern lifecycles,
and search performance boundaries without logging sensitive telemetry or credentials.
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict

logger = logging.getLogger("cyberguard.novelty_engine")


class NoveltyMetricsTracker:
    """Thread-safe in-memory metrics counter for Section 22 Novelty Engine."""

    def __init__(self):
        self._counters: Counter = Counter()

    def increment(self, metric_name: str, count: int = 1) -> None:
        self._counters[metric_name] += count

    def get_metrics(self) -> Dict[str, int]:
        return dict(self._counters)

    def record_assessment(self, is_novel: bool) -> None:
        self.increment("novelty_assessments")
        if is_novel:
            self.increment("novel_patterns_detected")
        else:
            self.increment("known_patterns_detected")

    def record_emerging_pattern(self, is_new: bool) -> None:
        if is_new:
            self.increment("emerging_patterns_created")
        else:
            self.increment("emerging_patterns_repeated")

    def record_search(self, candidate_count: int, hit_limit: bool = False) -> None:
        self.increment("similarity_searches")
        if hit_limit:
            self.increment("similarity_search_limits")

    def record_failure(self, reason: str = "general") -> None:
        self.increment(f"novelty_comparison_failures_{reason}")
        self.increment("novelty_comparison_failures")

    def record_insufficient_history(self) -> None:
        self.increment("novelty_history_insufficient")


# Global singleton tracker instance
novelty_metrics = NoveltyMetricsTracker()
