"""
Robust Behavioral Statistics & Anomaly Scoring (Section 21).

Provides outlier-resistant statistical metrics: Median, MAD (Median Absolute Deviation),
Winsorized statistics, Percentile ranges, Circular Distance (time-of-day),
and Laplace-smoothed Categorical Frequency distributions.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import math
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.schemas.behavioral_baseline import (
    BaselineConfidenceLevel,
    BaselinePercentiles,
    BaselineQuality,
    CircularHourDistribution,
    DeviationDirection,
)


class BehavioralStatisticsEngine:
    """
    Robust statistical calculation and anomaly deviation assessment engine.
    """

    @staticmethod
    def calculate_median(values: List[float]) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        mid = n // 2
        if n % 2 == 1:
            return float(sorted_vals[mid])
        return float((sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0)

    @staticmethod
    def calculate_mad(values: List[float], median: Optional[float] = None) -> float:
        """
        Calculates Median Absolute Deviation:
        MAD = median(|x_i - median(X)|)
        """
        if not values:
            return 0.0
        if median is None:
            median = BehavioralStatisticsEngine.calculate_median(values)
        abs_deviations = [abs(x - median) for x in values]
        return BehavioralStatisticsEngine.calculate_median(abs_deviations)

    @staticmethod
    def calculate_percentiles(values: List[float]) -> BaselinePercentiles:
        if not values:
            return BaselinePercentiles()
        sorted_vals = sorted(values)
        n = len(sorted_vals)

        def get_p(p: float) -> float:
            idx = int(p * (n - 1))
            return float(sorted_vals[idx])

        return BaselinePercentiles(
            p10=get_p(0.10),
            p25=get_p(0.25),
            p50=get_p(0.50),
            p75=get_p(0.75),
            p90=get_p(0.90),
            p95=get_p(0.95),
            p99=get_p(0.99),
        )

    @classmethod
    def winsorize(cls, values: List[float], trim_fraction: float = 0.02) -> List[float]:
        """Clamps top and bottom fractions of samples to resist extreme contamination."""
        if len(values) < 10:
            return list(values)
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        k = max(1, int(n * trim_fraction))
        low_val = sorted_vals[k]
        high_val = sorted_vals[-k - 1]
        return [min(max(x, low_val), high_val) for x in values]

    @classmethod
    def circular_hour_distance(cls, h1: float, h2: float) -> float:
        """
        Calculates minimum circular distance in hours on a 24-hour clock.
        d(h1, h2) = min(|h1 - h2|, 24 - |h1 - h2|)
        Example: distance between 23.0 and 1.0 is 2.0 hours.
        """
        diff = abs(h1 - h2) % 24.0
        return min(diff, 24.0 - diff)

    @classmethod
    def build_circular_hour_distribution(cls, hour_samples: List[float]) -> CircularHourDistribution:
        """Constructs circular hourly histogram and contiguous activity clusters."""
        if not hour_samples:
            return CircularHourDistribution()

        hour_bins: Dict[int, int] = {h: 0 for h in range(24)}
        for h in hour_samples:
            bin_idx = int(math.floor(h)) % 24
            hour_bins[bin_idx] += 1

        active = [h for h, cnt in hour_bins.items() if cnt > 0]
        string_bins = {str(k): v for k, v in hour_bins.items() if v > 0}

        # Overnight check (hours between 00:00 and 05:00)
        overnight = any(hour_bins[h] > 0 for h in range(0, 6))

        start_h = min(active) if active else None
        end_h = max(active) if active else None

        return CircularHourDistribution(
            active_hours=sorted(active),
            hour_counts=string_bins,
            primary_cluster_start=start_h,
            primary_cluster_end=end_h,
            overnight_active=overnight,
        )

    @classmethod
    def evaluate_numerical_deviation(
        cls,
        observed: float,
        median: float,
        mad: float,
        percentiles: Optional[BaselinePercentiles] = None,
        is_rate_or_volume: bool = False,
    ) -> Tuple[float, DeviationDirection, str]:
        """
        Evaluates numerical observation against median and MAD using robust Modified Z-Score:
        M = 0.6745 * |x - median| / (MAD + eps)
        Returns (deviation_score: 0.0-1.0, direction, explanation).
        """
        eps = 1e-4
        diff = observed - median
        direction = DeviationDirection.ABOVE_NORMAL if diff > 0 else DeviationDirection.BELOW_NORMAL

        if mad < eps:
            # If MAD is near zero, use percentage deviation or direct difference
            if abs(diff) < eps:
                return 0.0, DeviationDirection.CHANGED, "Observed value exactly matches historical median."
            mod_z = abs(diff) / max(1.0, abs(median) * 0.2)
        else:
            mod_z = (0.6745 * abs(diff)) / mad

        # Map modified Z-score to bounded 0.0 - 1.0 deviation score
        # Z <= 2.5: Normal (< 0.3)
        # Z = 3.5: Moderate Anomaly (0.5 - 0.7)
        # Z >= 6.0: High Anomaly (>= 0.85)
        raw_score = 1.0 - math.exp(-0.35 * max(0.0, mod_z - 2.0)) if mod_z > 2.0 else 0.0
        deviation_score = max(0.0, min(1.0, raw_score))

        p_summary = f"median={median:.2f}, MAD={mad:.2f}"
        if percentiles and percentiles.p25 is not None and percentiles.p75 is not None:
            p_summary += f", IQR=[{percentiles.p25:.2f}, {percentiles.p75:.2f}]"

        expl = (
            f"Observed value ({observed:.2f}) deviates from historical baseline ({p_summary}) "
            f"with modified Z-score of {mod_z:.2f}."
        )
        return deviation_score, direction, expl

    @classmethod
    def evaluate_circular_hour_deviation(
        cls,
        observed_hour: float,
        dist: CircularHourDistribution,
    ) -> Tuple[float, DeviationDirection, str]:
        """
        Evaluates observed login hour (0-23) against circular hour distribution.
        """
        if not dist.active_hours:
            return 0.0, DeviationDirection.CHANGED, "No active historical hour baseline."

        # Find minimum circular distance to any historically active hour
        min_dist = min(cls.circular_hour_distance(observed_hour, float(h)) for h in dist.active_hours)

        if min_dist <= 1.0:
            return 0.0, DeviationDirection.CHANGED, "Observed time is within normal historical hours."

        # Distance > 1 hour is unusual; distance > 4 hours is significant deviation
        # Map min_dist (0 to 12) to deviation score
        score = min(1.0, (min_dist - 1.0) / 6.0)
        direction = DeviationDirection.ABOVE_NORMAL if observed_hour > (dist.primary_cluster_end or 18) else DeviationDirection.BELOW_NORMAL

        obs_h_int = int(math.floor(observed_hour))
        obs_m_int = int((observed_hour - obs_h_int) * 60)
        time_str = f"{obs_h_int:02d}:{obs_m_int:02d}"

        active_range_str = f"{min(dist.active_hours):02d}:00–{max(dist.active_hours):02d}:59"
        expl = (
            f"Observed activity at {time_str} is {min_dist:.1f} hours outside the entity's established "
            f"historical schedule ({active_range_str})."
        )
        return score, direction, expl

    @classmethod
    def evaluate_categorical_deviation(
        cls,
        observed_category: str,
        distribution: Dict[str, int],
        total_samples: int,
    ) -> Tuple[float, DeviationDirection, str]:
        """
        Evaluates categorical observation (device, source IP, endpoint, method).
        """
        clean_cat = str(observed_category).strip()
        count = distribution.get(clean_cat, 0)

        if count > 0:
            freq = count / max(1, total_samples)
            if freq >= 0.15:
                return 0.0, DeviationDirection.CHANGED, f"Observed category '{clean_cat}' is well-established ({count}/{total_samples} historical events)."
            elif freq >= 0.05:
                return 0.25, DeviationDirection.CHANGED, f"Observed category '{clean_cat}' is infrequently observed ({count}/{total_samples} events)."
            else:
                return 0.45, DeviationDirection.CHANGED, f"Observed category '{clean_cat}' is rarely observed ({count}/{total_samples} events)."

        # Entirely NEW category
        unique_seen = len(distribution)
        # If the entity only has 1 known category across 50 events, seeing a new one is highly anomalous
        # If the entity uses 30 different IPs, seeing a new one is much less anomalous
        if unique_seen <= 2 and total_samples >= 15:
            score = 0.85
        elif unique_seen <= 5 and total_samples >= 10:
            score = 0.65
        else:
            score = 0.45

        expl = (
            f"Observed value '{clean_cat}' has not been previously observed in historical baseline "
            f"(established baseline comprises {unique_seen} known value(s) across {total_samples} samples)."
        )
        return score, DeviationDirection.NEW, expl

    @classmethod
    def assess_baseline_quality(
        cls,
        sample_count: int,
        window_start: Optional[datetime],
        window_end: Optional[datetime],
        missing_count: int = 0,
        is_frozen: bool = False,
    ) -> Tuple[BaselineQuality, float, BaselineConfidenceLevel]:
        """
        Determines baseline quality state and confidence score based on sample volume and time span.
        """
        if sample_count == 0:
            return BaselineQuality.NO_DATA, 0.0, BaselineConfidenceLevel.VERY_LOW

        if sample_count < 5:
            return BaselineQuality.INSUFFICIENT_HISTORY, 0.20, BaselineConfidenceLevel.VERY_LOW

        time_span_days = 0.0
        if window_start and window_end:
            time_span_days = max(0.0, (window_end - window_start).total_seconds() / 86400.0)

        # Check staleness: if last update was more than 45 days ago
        now = datetime.now(timezone.utc)
        if window_end and (now - window_end.replace(tzinfo=timezone.utc if window_end.tzinfo is None else window_end.tzinfo)).days > 45:
            return BaselineQuality.STALE, 0.40, BaselineConfidenceLevel.LOW

        missing_ratio = missing_count / max(1, sample_count + missing_count)
        if missing_ratio > 0.40:
            return BaselineQuality.DEGRADED, 0.35, BaselineConfidenceLevel.LOW

        if sample_count < 15 or time_span_days < 7.0:
            return BaselineQuality.DEVELOPING, 0.55, BaselineConfidenceLevel.MODERATE

        if sample_count >= 30 and time_span_days >= 14.0:
            return BaselineQuality.STABLE, 0.90, BaselineConfidenceLevel.HIGH

        return BaselineQuality.STABLE, 0.80, BaselineConfidenceLevel.HIGH
