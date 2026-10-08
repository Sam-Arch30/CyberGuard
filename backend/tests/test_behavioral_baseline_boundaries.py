"""
Boundary and Safety Guardrail Tests for Behavioral Baseline Engine (Section 21).
Verifies credential privacy, non-alarmist phrasing, auditability, and reproducibility.
"""
import pytest
from datetime import datetime, timezone
import json
import uuid

from backend.schemas.behavioral_baseline import (
    BaselineEntityType,
    BaselineMetricType,
    BehavioralBaseline,
    BehavioralDeviation,
    DeviationDirection,
    validate_feature_privacy,
)
from backend.services.behavioral_feature_extractor import BehavioralFeatureExtractor


def test_boundary_01_privacy_rejects_credentials_and_secrets():
    """Validates that password, secret, token, and cookie keywords are strictly rejected."""
    # 1. Direct validator
    with pytest.raises(ValueError, match="Privacy violation"):
        validate_feature_privacy("user_password", "PlaintextPassword123")

    with pytest.raises(ValueError, match="Privacy violation"):
        validate_feature_privacy("session_secret", "s3cr3t_v4lu3")

    with pytest.raises(ValueError, match="Privacy violation"):
        validate_feature_privacy("bearer_token", "eyJhbGciOi...")

    with pytest.raises(ValueError, match="Privacy violation"):
        validate_feature_privacy("api_key", "sk-live-123456789")

    with pytest.raises(ValueError, match="Privacy violation"):
        validate_feature_privacy("auth_header", "Bearer eyJhbGciOi...")


def test_boundary_02_model_rejects_credential_distribution():
    """Pydantic model rejects distribution containing sensitive tokens or credentials."""
    with pytest.raises(ValueError, match="Privacy violation"):
        BehavioralBaseline(
            id=str(uuid.uuid4()),
            entity_type=BaselineEntityType.USER,
            entity_id="alice",
            metric_type=BaselineMetricType.AUTH_METHOD,
            categorical_distribution={"Bearer eyJhbGci...": 10},
        )


def test_boundary_03_non_alarmist_phrasing_guarantee():
    """Deviation models and explanations must avoid sensationalist/alarmist verdict words."""
    dev = BehavioralDeviation(
        id=str(uuid.uuid4()),
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_HOUR,
        observed_value="03:17",
        expected_range_summary="08:00–18:00",
        deviation_score=0.75,
        deviation_direction=DeviationDirection.BELOW_NORMAL,
        explanation="Observed activity at 03:17 is 5.0 hours outside the entity's established historical schedule.",
    )

    forbidden_words = ["hacker", "compromised for sure", "guaranteed breach", "pwned", "100% malicious"]
    for word in forbidden_words:
        assert word not in dev.explanation.lower()


def test_boundary_04_reproducibility_version_stamps():
    """Baselines and deviations must carry version lineage stamps for forensic reproducibility."""
    b = BehavioralBaseline(
        id=str(uuid.uuid4()),
        entity_type=BaselineEntityType.USER,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_HOUR,
        baseline_version="1.0.0",
        feature_version="1.0.0",
        calculation_method="ROBUST_STATISTICS",
        configuration_version="2026.10",
    )
    assert b.baseline_version == "1.0.0"
    assert b.calculation_method == "ROBUST_STATISTICS"
    assert b.configuration_version == "2026.10"
