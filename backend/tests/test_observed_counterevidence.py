import json


def test_observed_counterevidence_is_preserved():
    from backend.services.analysis_results_aggregator import AnalysisResultsAggregator
    from backend.db.models import ArtifactModel, AnalysisRunModel, FindingModel

    artifact = ArtifactModel(id="observed-email", artifact_type="EMAIL", name="fixture.eml")
    run = AnalysisRunModel(id="observed-run", artifact_id=artifact.id)
    finding = FindingModel(
        id="observed-finding", analyzer="fixture",
        metadata_json=json.dumps({"counter_evidence": ["Observed aligned DKIM signature"]}),
    )
    items = AnalysisResultsAggregator._build_counter_evidence([finding], run, artifact)
    assert len(items) == 1
    assert items[0].title == "Observed aligned DKIM signature"
    assert items[0].source == "fixture"
    assert "age" not in items[0].title.lower()
