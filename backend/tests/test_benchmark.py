"""
Comprehensive Unit and Integration Tests for the MailTraceAI SIH Benchmark and Demo System.
Validates:
- Labelled evaluation dataset integrity (60 samples: 30 legitimate, 30 malicious)
- The 3 SIH synthetic scenarios (False-positive resistance, Phishing detection, Campaign correlation)
- Dynamic latency measurement (Mean, Median, P95)
- Detection performance metrics (Precision, Recall, F1, FPR, FNR)
- API endpoints (/api/benchmark/latest, /api/benchmark/run, /api/benchmark/scenarios, /api/benchmark/demo-reset)
- Data separation and strict synthetic tagging
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.benchmark_service import BenchmarkService, global_benchmark_service
from backend.data.sih_scenarios import (
    SCENARIO_1_LEGITIMATE,
    SCENARIO_2_PHISHING,
    SCENARIO_3_PRIMARY_EMAIL,
    SCENARIO_3_CAMPAIGN_CLUSTER
)

client = TestClient(app)


class TestSIHScenarios:
    def test_scenario_1_legitimate_false_positive_resistance(self):
        """Scenario 1 must exhibit LOW threat score (< 15) and full auth pass."""
        sc1 = SCENARIO_1_LEGITIMATE
        assert sc1["is_demo"] is True
        assert sc1["dataset"] == "synthetic_sih_demo"
        assert sc1["threat_score"]["score"] < 15
        assert sc1["threat_score"]["severity"] == "low"
        assert sc1["authentication"]["spf"]["result"] == "pass"
        assert sc1["authentication"]["dkim"]["result"] == "pass"
        assert sc1["authentication"]["dmarc"]["result"] == "pass"
        # Safe attachment inspection
        att = sc1["indicators"]["attachments"][0]
        assert att["static_analysis"]["is_executable"] is False
        assert att["static_analysis"]["contains_macros"] is False
        assert att["static_analysis"]["mismatch_detected"] is False

    def test_scenario_2_obvious_phishing_detection(self):
        """Scenario 2 must exhibit CRITICAL threat score (> 75), lookalike brand, and disguised executable."""
        sc2 = SCENARIO_2_PHISHING
        assert sc2["is_demo"] is True
        assert sc2["dataset"] == "synthetic_sih_demo"
        assert sc2["threat_score"]["score"] > 75
        assert sc2["threat_score"]["severity"] == "critical"
        assert sc2["authentication"]["spf"]["result"] == "fail"
        assert sc2["authentication"]["dkim"]["result"] == "fail"
        assert sc2["authentication"]["dmarc"]["result"] == "fail"
        assert sc2["authentication"]["alignment"]["reply_to_mismatch"] is True
        # Disguised executable payload inspection
        att = sc2["indicators"]["attachments"][0]
        assert att["filename"] == "Security_Notice.pdf.exe"
        assert att["static_analysis"]["is_executable"] is True
        assert att["static_analysis"]["extension_mismatch"] is True
        assert att["static_analysis"]["double_extension"] is True
        assert att["static_analysis"]["entropy"] > 7.5

    def test_scenario_3_coordinated_campaign(self):
        """Scenario 3 must correlate with Campaign C-042 and 16 related emails."""
        sc3 = SCENARIO_3_PRIMARY_EMAIL
        assert sc3["is_demo"] is True
        assert sc3["threat_score"]["score"] >= 90
        assert sc3["campaign_correlation"]["has_correlation"] is True
        assert sc3["campaign_correlation"]["campaign_id"] == "C-042"
        assert sc3["campaign_correlation"]["related_email_count"] == 16
        # Validate cluster contains exactly 16 correlated messages
        assert len(SCENARIO_3_CAMPAIGN_CLUSTER) == 16
        for email in SCENARIO_3_CAMPAIGN_CLUSTER:
            assert email["asn"] == "AS64512"
            assert "203.0.113." in email["origin_ip"]
            assert email["threat_score"] >= 85


class TestBenchmarkEngine:
    def test_labelled_dataset_balance(self):
        """Evaluation dataset must have 60 samples (30 legitimate, 30 malicious)."""
        bench = BenchmarkService()
        assert bench.DATASET_PATH.exists()
        import json
        with open(bench.DATASET_PATH, "r") as f:
            data = json.load(f)
        assert len(data) == 60
        legit = [d for d in data if d.get("ground_truth") == "legitimate"]
        malicious = [d for d in data if d.get("ground_truth") == "malicious"]
        assert len(legit) == 30
        assert len(malicious) == 30

    def test_dynamic_benchmark_execution_and_metrics(self):
        """Run genuine benchmark evaluation and verify authentic metrics calculations."""
        res = global_benchmark_service.run_benchmark()
        assert "run_id" in res
        assert res["total_samples"] == 60
        assert res["legitimate_count"] == 30
        assert res["malicious_count"] == 30

        # Detection Performance
        d = res["detection_metrics"]
        assert d["accuracy"] >= 0.90
        assert d["precision"] >= 0.90
        assert d["recall"] >= 0.90
        assert d["f1_score"] >= 0.90
        assert d["false_positive_rate"] <= 0.05
        cm = d["confusion_matrix"]
        assert cm["true_positive"] + cm["false_positive"] + cm["true_negative"] + cm["false_negative"] == 60

        # Latency Metrics (must be non-negative real numbers)
        lat = res["latency_metrics"]
        for key in ["ioc_extraction", "authentication_analysis", "threat_scoring", "total_analysis"]:
            assert key in lat
            assert lat[key]["mean"] >= 0.0
            assert lat[key]["median"] >= 0.0
            assert lat[key]["p95"] >= 0.0


class TestBenchmarkAPI:
    def test_get_latest_benchmark_endpoint(self):
        res = client.get("/api/benchmark/latest")
        assert res.status_code == 200
        data = res.json()
        assert "run_id" in data
        assert "detection_metrics" in data
        assert "latency_metrics" in data
        assert data["total_samples"] == 60

    def test_post_run_benchmark_endpoint(self):
        res = client.post("/api/benchmark/run")
        assert res.status_code == 200
        data = res.json()
        assert data["run_id"].startswith("BENCH-")
        assert data["model_version"] == "v4.2-explainable"
        assert data["dataset_version"] == "v1.4-SIH-SAFE"

    def test_get_scenarios_endpoint(self):
        res = client.get("/api/benchmark/scenarios")
        assert res.status_code == 200
        data = res.json()
        assert "scenarios" in data
        assert len(data["scenarios"]) == 3
        ids = [s["id"] for s in data["scenarios"]]
        assert "scenario-1-legit" in ids
        assert "scenario-2-phish" in ids
        assert "scenario-3-campaign" in ids

    def test_demo_reset_endpoint(self):
        res = client.post("/api/benchmark/demo-reset")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["isolated"] is True
        assert data["synthetic_tag"] == "synthetic_sih_demo"
