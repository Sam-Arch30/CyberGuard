"""
Novelty Detection & Emerging-Threat Identification Configuration (Section 22).

Centralizes all resource limits, comparison bounds, retention windows,
and similarity thresholds to avoid scattered magic numbers across the codebase.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class NoveltyEngineConfig:
    # Retention & Historical Lookback
    MAX_HISTORY_LOOKBACK_DAYS: int = 90
    DEFAULT_COMPARISON_WINDOW: str = "90_DAYS"

    # Search & Comparison Limits (Prevent O(N^2) or unbounded execution)
    MAX_SIMILARITY_CANDIDATES: int = 100
    MAX_NOVELTY_COMPARISONS: int = 200
    MAX_SEQUENCE_LENGTH: int = 20
    MAX_FEATURE_COUNT: int = 50
    MAX_CLUSTER_SIZE: int = 100
    MAX_PATTERN_STORAGE: int = 10000

    # Categorical Novelty Thresholds (Relative Distance [0.0 - 1.0])
    THRESHOLD_KNOWN: float = 0.15      # novelty < 0.15 => KNOWN
    THRESHOLD_LOW: float = 0.40        # 0.15 <= novelty < 0.40 => LOW
    THRESHOLD_MODERATE: float = 0.70   # 0.40 <= novelty < 0.70 => MODERATE
    THRESHOLD_HIGH: float = 0.90       # 0.70 <= novelty < 0.90 => HIGH
    # novelty >= 0.90 => VERY_HIGH

    # Recurrence & Emerging Pattern Thresholds
    EMERGING_MIN_OBSERVATIONS: int = 2
    EMERGING_MIN_ENTITIES: int = 2
    EMERGING_MIN_INCIDENTS: int = 2
    EMERGING_RECURRENCE_WEIGHT_FREQ: float = 0.4
    EMERGING_RECURRENCE_WEIGHT_ENTITIES: float = 0.3
    EMERGING_RECURRENCE_WEIGHT_INCIDENTS: float = 0.3

    # Versioning
    ENGINE_VERSION: str = "1.0.0"
    FEATURE_VERSION: str = "1.0.0"
    NORMALIZATION_VERSION: str = "1.0.0"
    CONFIGURATION_VERSION: str = "2026.10"


DEFAULT_NOVELTY_CONFIG = NoveltyEngineConfig()
