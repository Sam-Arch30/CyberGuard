"""
Novelty Structural Similarity Service (Section 22).

Computes deterministic, lightweight structural similarity and novelty distance
between observed patterns and retained historical pattern libraries.
Supports sequence alignment, Jaccard token overlap, normalized Levenshtein edit distance,
and multi-attribute structural distance without heavyweight external ML libraries.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.config.novelty_config import DEFAULT_NOVELTY_CONFIG, NoveltyEngineConfig
from backend.schemas.novelty_detection import NoveltyLevel


class NoveltySimilarityService:
    """Calculates relative distance and structural similarity across pattern representations."""

    @classmethod
    def jaccard_similarity(cls, set_a: Set[Any], set_b: Set[Any]) -> float:
        """Computes Jaccard index between two sets: |A ∩ B| / |A ∪ B|."""
        if not set_a and not set_b:
            return 1.0
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return round(float(intersection) / float(union), 4)

    @classmethod
    def levenshtein_distance(cls, s1: str, s2: str) -> int:
        """Computes Levenshtein edit distance between two strings."""
        if s1 == s2:
            return 0
        if not s1:
            return len(s2)
        if not s2:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    @classmethod
    def normalized_levenshtein_similarity(cls, s1: str, s2: str) -> float:
        """Normalizes edit distance to similarity score in [0.0, 1.0]."""
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        dist = cls.levenshtein_distance(s1, s2)
        return round(max(0.0, 1.0 - (float(dist) / float(max_len))), 4)

    @classmethod
    def longest_common_subsequence_length(cls, seq1: List[str], seq2: List[str]) -> int:
        """Computes length of longest common subsequence between two token lists."""
        m, n = len(seq1), len(seq2)
        if m == 0 or n == 0:
            return 0

        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seq1[i - 1] == seq2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[m][n]

    @classmethod
    def sequence_similarity(cls, seq1: List[str], seq2: List[str]) -> float:
        """
        Computes composite sequence similarity combining:
        1. Longest Common Subsequence ratio (ordering preservation)
        2. Bigram transition overlap (local step preservation)
        """
        if not seq1 and not seq2:
            return 1.0
        if not seq1 or not seq2:
            return 0.0

        # 1. LCS ratio
        lcs_len = cls.longest_common_subsequence_length(seq1, seq2)
        lcs_ratio = (2.0 * lcs_len) / float(len(seq1) + len(seq2))

        # 2. Bigrams
        def get_bigrams(seq: List[str]) -> Set[Tuple[str, str]]:
            return {(seq[i], seq[i + 1]) for i in range(len(seq) - 1)}

        bg1 = get_bigrams(seq1)
        bg2 = get_bigrams(seq2)
        bg_sim = cls.jaccard_similarity(bg1, bg2) if (bg1 or bg2) else lcs_ratio

        # Weighted combination: 60% LCS + 40% Transition bigrams
        composite = 0.60 * lcs_ratio + 0.40 * bg_sim
        return round(composite, 4)

    @classmethod
    def structural_attribute_similarity(cls, attrs1: Dict[str, Any], attrs2: Dict[str, Any]) -> float:
        """
        Computes structural match between two attribute dictionaries.
        Compares shared keys, rewarding exact matches and penalized missing/divergent structure.
        """
        all_keys = set(attrs1.keys()).union(set(attrs2.keys()))
        if not all_keys:
            return 1.0

        matches = 0.0
        for k in all_keys:
            v1 = attrs1.get(k)
            v2 = attrs2.get(k)
            if v1 is None or v2 is None:
                continue

            if v1 == v2:
                matches += 1.0
            elif isinstance(v1, list) and isinstance(v2, list):
                matches += cls.jaccard_similarity(set(v1), set(v2))
            elif isinstance(v1, str) and isinstance(v2, str):
                matches += cls.normalized_levenshtein_similarity(v1, v2)

        return round(matches / float(len(all_keys)), 4)

    @classmethod
    def evaluate_candidates(
        cls,
        observed_attrs: Dict[str, Any],
        historical_candidates: List[Dict[str, Any]],
        config: NoveltyEngineConfig = DEFAULT_NOVELTY_CONFIG,
    ) -> Tuple[float, float, NoveltyLevel, Optional[str]]:
        """
        Evaluates an observed pattern against retained historical candidates.
        Returns:
            (novelty_score, max_similarity_score, novelty_level, nearest_match_repr)
        """
        if not historical_candidates:
            # No prior history in retained telemetry -> Completely novel
            return (1.0, 0.0, NoveltyLevel.VERY_HIGH, None)

        max_sim = 0.0
        nearest_repr = None

        # Bound candidates to prevent runaway computation
        candidates_to_eval = historical_candidates[:config.MAX_SIMILARITY_CANDIDATES]

        for cand in candidates_to_eval:
            cand_attrs = cand.get("attributes", {})
            cand_repr = cand.get("fingerprint_repr", "")

            # Check if this is a sequence comparison
            if "sequence" in observed_attrs and "sequence" in cand_attrs:
                sim = cls.sequence_similarity(observed_attrs["sequence"], cand_attrs["sequence"])
            elif "route_template" in observed_attrs and "route_template" in cand_attrs:
                # API route comparison: method match (30%) + template edit distance (50%) + resource match (20%)
                method_match = 1.0 if observed_attrs.get("method") == cand_attrs.get("method") else 0.0
                template_sim = cls.normalized_levenshtein_similarity(
                    observed_attrs.get("route_template", ""),
                    cand_attrs.get("route_template", "")
                )
                res_match = 1.0 if observed_attrs.get("resource_type") == cand_attrs.get("resource_type") else 0.0
                sim = 0.30 * method_match + 0.50 * template_sim + 0.20 * res_match
            elif "path_template" in observed_attrs and "path_template" in cand_attrs:
                # URL structure comparison
                host_match = 1.0 if observed_attrs.get("hostname_type") == cand_attrs.get("hostname_type") else 0.0
                path_sim = cls.normalized_levenshtein_similarity(
                    observed_attrs.get("path_template", ""),
                    cand_attrs.get("path_template", "")
                )
                params_sim = cls.jaccard_similarity(
                    set(observed_attrs.get("param_keys", [])),
                    set(cand_attrs.get("param_keys", []))
                )
                sim = 0.30 * host_match + 0.40 * path_sim + 0.30 * params_sim
            else:
                sim = cls.structural_attribute_similarity(observed_attrs, cand_attrs)

            if sim > max_sim:
                max_sim = sim
                nearest_repr = cand_repr
                if max_sim >= 0.999:
                    break  # Exact match found

        novelty_score = round(max(0.0, min(1.0, 1.0 - max_sim)), 4)
        level = cls.score_to_level(novelty_score, config)
        return (novelty_score, round(max_sim, 4), level, nearest_repr)

    @classmethod
    def score_to_level(cls, score: float, config: NoveltyEngineConfig = DEFAULT_NOVELTY_CONFIG) -> NoveltyLevel:
        """Translates numeric relative distance [0.0 - 1.0] to controlled NoveltyLevel."""
        if score < config.THRESHOLD_KNOWN:
            return NoveltyLevel.KNOWN
        elif score < config.THRESHOLD_LOW:
            return NoveltyLevel.LOW
        elif score < config.THRESHOLD_MODERATE:
            return NoveltyLevel.MODERATE
        elif score < config.THRESHOLD_HIGH:
            return NoveltyLevel.HIGH
        else:
            return NoveltyLevel.VERY_HIGH
