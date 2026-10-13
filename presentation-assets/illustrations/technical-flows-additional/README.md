# Additional source-grounded CyberGuard flowcharts

Four six-box diagrams; original PNGs and editable SVGs. Generated directly with Pillow/SVG, not an image-generation model. Drawings describe the code paths; no new accuracy evaluation or live detection validation is claimed.

5. Files/attachments: backend/services/file_security_pipeline.py::FileSecurityPipeline.analyze_file and backend/services/file_security_analyzers.py. This is the focused file API, not the narrower generic ingestion DAG. Supported format-specific checks are conditional. Hash reputation depends on configured services. Unknown/no-match is not proof of safety.

6. Network anomalies: backend/services/network_pipeline.py::NetworkSecurityPipeline.analyze_events and backend/services/network_analyzers.py::{ConnectionPatternEngine,PeriodicityEngine,DnsTelemetryEngine,TransferExfiltrationEngine,DestinationAnomalyEngine,NetworkPatternAggregator}. Detection is over submitted event batches. It does not imply continuous packet capture or automatic prevention.

7. API abuse: backend/services/api_pipeline.py::APISecurityPipeline.analyze_events and backend/services/api_analyzers.py. Includes normalized secret-redacted telemetry, deduplication, temporal ordering, account baselines, configured rule engines, existing-record cross-module correlations and hypothesis aggregation. Empty/malformed telemetry handling and calibration remain limitations of the code; no performance guarantee is claimed.

8. Audio spectral heuristics: backend/services/media_decoder.py::decode_media and backend/services/multimedia_service.py::AudioSpectralAcousticDetector / MultimediaPipeline.analyze_media. The local bounded decoder produces mono 44.1 kHz PCM WAV. The detector normalizes samples, computes a SciPy real FFT, high-frequency energy above 8 kHz and spectral flatness, then applies an abrupt-cutoff rule. No MFCC extractor, speaker-verification model, trained voice-clone detector or calibrated probability is invented. These heuristics can flag compression or recording properties; they do not establish voice cloning. Decode failures return limitations rather than proceeding through every box.

Regenerate with backend/venv/Scripts/python.exe presentation-assets/illustrations/technical-flows-additional/generate_flows.py.
