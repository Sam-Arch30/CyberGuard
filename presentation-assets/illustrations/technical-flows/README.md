# CyberGuard source-grounded technical flowcharts

Four standalone PNGs and editable SVGs, plus a 2×2 PNG overview. Each chart has six rectangular boxes and simple arrows. White background, cream process boxes, lavender result boxes, no Start/End ovals or decorative icons. Drawn programmatically; no image-generation model was used.

## Source mapping

1. Email: `backend/api/routes/email.py::analyze_email`; `backend/services/email_parser.py::EmailParserService.parse_eml_bytes`; `backend/app/ml/classifier.py::PhishingClassifier.predict`; `backend/services/threat_scorer.py::ThreatScorerService.calculate_score`. Parsing includes MIME, authentication headers, relay information, URLs and attachment observables. HTML is sanitized before enrichment; subject/body classification uses TextNormalizer and the loaded TF-IDF + Logistic Regression pipeline. Missing models yield unavailable ML results, not invented classification. The main scoring path includes available signals. The optional AI analyst narrative is omitted because it is not a required detection stage.

2. URL: `backend/services/url_domain_pipeline.py::URLDomainIntelligencePipeline.analyze_url`; `backend/services/url_domain_analyzers.py::{PassiveURLAnalyzer,DomainIntelligenceAnalyzer,SafeWebsiteAnalyzer}`; `backend/services/safe_http_client.py::SafeHttpClient`. Passive structure checks precede domain intelligence and optional active website inspection. Network and external intelligence availability affect results. This is the focused URL API; uploading a text list does not automatically run this flow for every extracted URL.

3. Identity: `backend/services/identity_contract.py::normalize_email_claim`; `backend/schemas/impersonation.py::ImpersonationAnalysisRequest.validate_claim`; `backend/services/impersonation_service.py::{IdentityClaimExtractor,IdentityComparisonService,DigitalImpersonationPipeline}`. This compact chart shows the email-sender identity path. Addresses are parsed and domains derived server-side. A protected reference profile is required for authoritative comparison; missing profiles can yield insufficient evidence. Score synthesis discounts counter-evidence and caps the supporting risk total.

4. Authentication: `backend/services/auth_log_parser.py::parse_auth_log`; `backend/services/authentication_pipeline.py::AuthenticationSecurityPipeline.analyze_events`; `backend/services/authentication_analyzers.py`. The diagram groups existing rule engines to stay compact. Other implemented rules include failure analysis, temporal patterns and session analysis; historical checks depend on available profiles. Rule implementation is not a claim of validated accuracy across every provider.

## Why voice-clone and deepfake diagrams were replaced

`backend/services/multimedia_service.py::AudioSpectralAcousticDetector` computes audio spectral heuristics; it is not a trained voice-clone detector. `backend/services/deepfake_detector.py::predict_faces` has a research-only face classifier, but normal operation returns `MODEL_NOT_VALIDATED` after model/dependency checks. The model failed collected sample validation. Therefore these are not presented as working voice/deepfake detection modules. Authentication and identity were substituted to satisfy the requirement for four implemented modules.

These diagrams describe source structure, not a new runtime benchmark or a guarantee of successful threat detection. Existing scoring/calibration and reporting limitations remain.

Regenerate from the project root with:

`backend/venv/Scripts/python.exe presentation-assets/illustrations/technical-flows/generate_flows.py`
