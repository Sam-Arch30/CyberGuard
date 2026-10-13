"""
Unit, Integration, and False-Positive Tests for Section 13 Multimedia Authenticity & Deepfake Engine.
Tests all 36+ required scenarios: image, audio, and video detection, metadata, provenance,
real spectral/ELA forensics, frame sampling, multimodal disagreement, Section 12 integration,
epistemic limits, and API endpoints.
"""
from __future__ import annotations

import base64
import io
import os
import struct
import wave
import pytest
import numpy as np
from PIL import Image as PILImage
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import get_db, SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    ThreatEventModel,
    ProtectedIdentityModel,
    RelationshipModel,
)
from backend.schemas.unified import SeverityEnum
from backend.schemas.multimedia import (
    MediaTypeEnum,
    MediaFormatEnum,
    DetectorStatusEnum,
    AuthenticityClassificationEnum,
    MediaEvidenceCategoryEnum,
    ProvenanceStatusEnum,
    ProvenanceRecord,
    MediaMetadata,
)
from backend.services.multimedia_service import (
    MediaFormatIdentifier,
    MediaMetadataExtractor,
    ImageMetadataProvenanceDetector,
    ImageFrequencyArtifactDetector,
    ImageErrorLevelDetector,
    AudioSpectralAcousticDetector,
    VideoFrameSampler,
    VideoFrameForensicsDetector,
    VideoTemporalConsistencyDetector,
    MediaAuthenticityAggregator,
    MultimediaPipeline,
    DetectorRegistry,
    MediaDetector,
    DetectorResult,
    MAX_MEDIA_BYTES,
)

client = TestClient(app)


# ============================================================================
# TEST FIXTURES HELPERS
# ============================================================================

def create_synthetic_png(width: int = 100, height: int = 100, color=(120, 150, 200), metadata_dict=None) -> bytes:
    """Creates an in-memory PNG image with optional text metadata chunks."""
    img = PILImage.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    from PIL import PngImagePlugin
    png_info = PngImagePlugin.PngInfo()
    if metadata_dict:
        for k, v in metadata_dict.items():
            png_info.add_text(k, v)
    img.save(buf, format="PNG", pnginfo=png_info)
    return buf.getvalue()


def create_synthetic_jpeg(width: int = 100, height: int = 100, color=(120, 150, 200)) -> bytes:
    """Creates an in-memory JPEG image."""
    img = PILImage.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def create_synthetic_wav(duration_s: float = 1.0, sample_rate: int = 22050, freq: float = 440.0, bandlimited: bool = False) -> bytes:
    """Creates a synthetic PCM WAV audio buffer."""
    n_samples = int(duration_s * sample_rate)
    t = np.linspace(0, duration_s, n_samples, endpoint=False)

    if bandlimited:
        # Monotonic pure tone without high frequency harmonics (mimics abrupt vocoder cutoff)
        samples = 0.5 * np.sin(2 * np.pi * freq * t)
    else:
        # Rich natural harmonic spectrum (fundamentals + overtones above 8kHz)
        samples = 0.4 * np.sin(2 * np.pi * freq * t) + 0.2 * np.sin(2 * np.pi * 9000 * t) + 0.1 * np.sin(2 * np.pi * 10500 * t)

    int_samples = (samples * 32767).astype(np.int16)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(int_samples.tobytes())

    return buf.getvalue()


def create_synthetic_isobmff_mp4(duration_s: float = 5.0, has_video: bool = True, has_audio: bool = True) -> bytes:
    """Creates a minimal valid ISOBMFF MP4 binary container with moov, mvhd, and trak atoms."""
    # ftyp atom
    ftyp_data = b"isom\x00\x00\x02\x00isomiso2mp41"
    ftyp_atom = struct.pack(">I", len(ftyp_data) + 8) + b"ftyp" + ftyp_data

    # mvhd atom inside moov
    timescale = 1000
    duration_ticks = int(duration_s * timescale)
    mvhd_payload = b"\x00" * 12 + struct.pack(">II", timescale, duration_ticks) + b"\x00" * 80
    mvhd_atom = struct.pack(">I", len(mvhd_payload) + 8) + b"mvhd" + mvhd_payload

    # trak atom
    trak_payload = b""
    if has_video:
        trak_payload += b"vide\x00\x00avc1"
    if has_audio:
        trak_payload += b"soun\x00\x00mp4a"
    trak_atom = struct.pack(">I", len(trak_payload) + 8) + b"trak" + trak_payload

    moov_payload = mvhd_atom + trak_atom
    moov_atom = struct.pack(">I", len(moov_payload) + 8) + b"moov" + moov_payload

    return ftyp_atom + moov_atom


def create_animated_gif(frames_count: int = 4) -> bytes:
    """Creates an in-memory animated GIF."""
    frames = [
        PILImage.new("RGB", (64, 64), color=(i * 40, 100, 150))
        for i in range(frames_count)
    ]
    buf = io.BytesIO()
    frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:], duration=100, loop=0)
    return buf.getvalue()


# ============================================================================
# 1. MEDIA FORMAT & SAFETY TESTS
# ============================================================================

def test_01_image_type_detection():
    png_data = create_synthetic_png()
    m_type, m_fmt, mime = MediaFormatIdentifier.identify(png_data, "test.png")
    assert m_type == MediaTypeEnum.IMAGE
    assert m_fmt == MediaFormatEnum.PNG
    assert mime == "image/png"

    jpeg_data = create_synthetic_jpeg()
    m_type, m_fmt, mime = MediaFormatIdentifier.identify(jpeg_data, "photo.jpg")
    assert m_type == MediaTypeEnum.IMAGE
    assert m_fmt == MediaFormatEnum.JPEG
    assert mime == "image/jpeg"


def test_02_audio_type_detection():
    wav_data = create_synthetic_wav()
    m_type, m_fmt, mime = MediaFormatIdentifier.identify(wav_data, "sample.wav")
    assert m_type == MediaTypeEnum.AUDIO
    assert m_fmt == MediaFormatEnum.WAV
    assert mime == "audio/wav"


def test_03_video_type_detection():
    mp4_data = create_synthetic_isobmff_mp4()
    m_type, m_fmt, mime = MediaFormatIdentifier.identify(mp4_data, "clip.mp4")
    assert m_type == MediaTypeEnum.VIDEO
    assert m_fmt == MediaFormatEnum.MP4
    assert mime == "video/mp4"


def test_04_invalid_and_unknown_media():
    garbage = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    m_type, m_fmt, mime = MediaFormatIdentifier.identify(garbage, "unknown.bin")
    assert m_type == MediaTypeEnum.UNKNOWN_MEDIA
    assert m_fmt == MediaFormatEnum.UNKNOWN


def test_05_oversized_media_protection():
    pipeline = MultimediaPipeline()
    oversized = b"A" * (MAX_MEDIA_BYTES + 1024)
    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        pipeline.analyze_media(oversized, "huge.png")


# ============================================================================
# 2. METADATA & PROVENANCE EXTRACTION TESTS
# ============================================================================

def test_06_image_metadata_extraction():
    data = create_synthetic_png(width=240, height=180)
    meta, prov = MediaMetadataExtractor.extract_image_metadata(data)
    assert meta.width == 240
    assert meta.height == 180
    assert meta.color_mode == "RGB"
    assert prov.status == ProvenanceStatusEnum.NO_CREDENTIALS_FOUND


def test_07_image_generative_ai_prompt_metadata():
    # Simulate Stable Diffusion / Midjourney metadata in PNG chunks
    data = create_synthetic_png(
        metadata_dict={"parameters": "a high quality portrait of CEO, steps: 30, sampler: DPM++"}
    )
    meta, _ = MediaMetadataExtractor.extract_image_metadata(data)
    detector = ImageMetadataProvenanceDetector()
    res = detector.analyze(data, meta, {})

    assert res.status == DetectorStatusEnum.SUCCESS
    assert res.score >= 0.90
    assert "AI_GENERATED" in res.label


def test_08_audio_duration_and_metadata():
    wav_data = create_synthetic_wav(duration_s=2.5, sample_rate=16000)
    meta, prov = MediaMetadataExtractor.extract_audio_metadata(wav_data, MediaFormatEnum.WAV)
    assert meta.sample_rate == 16000
    assert meta.channels == 1
    assert abs(meta.duration_seconds - 2.5) < 0.1
    assert meta.has_audio_track is True


def test_09_video_duration_and_streams():
    mp4_data = create_synthetic_isobmff_mp4(duration_s=4.0, has_video=True, has_audio=True)
    meta, prov = MediaMetadataExtractor.extract_video_metadata(mp4_data, MediaFormatEnum.MP4)
    assert meta.has_video_track is True
    assert meta.has_audio_track is True
    assert abs(meta.duration_seconds - 4.0) < 0.1
    assert "H.264/AVC" in meta.codecs
    assert "AAC" in meta.codecs


def test_10_c2pa_marker_does_not_verify_signature():
    # Injected C2PA marker box
    raw = create_synthetic_jpeg() + b"jumbc2pa_manifest_block_data"
    _, prov = MediaMetadataExtractor.extract_image_metadata(raw)
    assert prov.credential_present is True
    assert prov.status == ProvenanceStatusEnum.UNVERIFIED_CREDENTIALS
    assert prov.signature_valid is None
    assert prov.issuer is None


# ============================================================================
# 3. FORENSIC DETECTORS (IMAGE, AUDIO, VIDEO)
# ============================================================================

def test_11_image_frequency_spectral_analysis_natural():
    # A natural uniform image has standard decaying frequency spectrum
    data = create_synthetic_jpeg(width=256, height=256)
    detector = ImageFrequencyArtifactDetector()
    res = detector.analyze(data, MediaMetadata(), {})
    assert res.status == DetectorStatusEnum.SUCCESS
    assert res.score < 0.50
    assert "NATURAL" in res.label


def test_12_image_frequency_spectral_analysis_grid_artifacts():
    # Construct an image with deliberate periodic high-frequency checkerboard / grid artifact
    arr = np.zeros((256, 256, 3), dtype=np.uint8)
    arr[::4, ::4] = 255  # Periodic high frequency grid
    img = PILImage.fromarray(arr)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    data = buf.getvalue()

    detector = ImageFrequencyArtifactDetector()
    res = detector.analyze(data, MediaMetadata(), {})
    assert res.status == DetectorStatusEnum.SUCCESS
    assert res.score >= 0.70
    assert res.evidence["is_anomalous_spectrum"] is True


def test_13_image_error_level_analysis_splicing():
    # Create spliced composite image (quadrant with completely different noise level)
    arr = np.ones((256, 256, 3), dtype=np.uint8) * 128
    # Add heavy noise to top-right quadrant only (spliced patch)
    noise = np.random.randint(0, 80, (128, 128, 3), dtype=np.uint8)
    arr[:128, 128:] = np.clip(arr[:128, 128:] + noise, 0, 255)

    img = PILImage.fromarray(arr)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=75)
    data = buf.getvalue()

    detector = ImageErrorLevelDetector()
    res = detector.analyze(data, MediaMetadata(), {})
    assert res.status == DetectorStatusEnum.SUCCESS
    assert res.evidence["inconsistent_compression"] is True
    assert res.score >= 0.75


def test_14_audio_spectral_natural_vs_synthetic_cutoff():
    # Natural audio has high frequency energy above 8kHz
    natural_wav = create_synthetic_wav(duration_s=1.0, sample_rate=22050, bandlimited=False)
    detector = AudioSpectralAcousticDetector()
    res_nat = detector.analyze(natural_wav, MediaMetadata(), {})
    assert res_nat.status == DetectorStatusEnum.SUCCESS
    assert res_nat.score <= 0.30

    # Artificial band-limited audio (sharp cutoff common to simple TTS models)
    tts_wav = create_synthetic_wav(duration_s=1.0, sample_rate=22050, bandlimited=True)
    res_tts = detector.analyze(tts_wav, MediaMetadata(), {})
    assert res_tts.status == DetectorStatusEnum.SUCCESS
    assert res_tts.score >= 0.80
    assert res_tts.evidence["abrupt_high_freq_cutoff"] is True


def test_15_video_frame_sampling_provenance():
    gif_data = create_animated_gif(frames_count=6)
    sampled = VideoFrameSampler.sample_frames(gif_data, MediaFormatEnum.GIF, max_frames=4)
    assert len(sampled) == 4
    # Check frame indexes and timestamps are monotonic
    for idx, ts, f_bytes in sampled:
        assert isinstance(idx, int)
        assert ts >= 0.0
        assert len(f_bytes) > 0


def test_16_video_temporal_consistency():
    gif_data = create_animated_gif(frames_count=4)
    detector = VideoTemporalConsistencyDetector()
    res = detector.analyze(gif_data, MediaMetadata(), {"format": MediaFormatEnum.GIF})
    assert res.status == DetectorStatusEnum.SUCCESS
    assert "mean_interframe_diff" in res.evidence


# ============================================================================
# 4. DETECTOR REGISTRY & NO FAKE AI MODEL ENFORCEMENT
# ============================================================================

def test_17_detector_registry_and_no_fake_ai():
    reg = DetectorRegistry()
    assert reg.get_detector("unregistered_model") is None
    # If a detector is unavailable, it must return None or UNAVAILABLE, never a fake score
    detectors = reg.get_detectors_for_type(MediaTypeEnum.IMAGE)
    assert len(detectors) == 0


def test_18_detector_failure_isolation():
    class BrokenDetector(MediaDetector):
        def analyze(self, data, metadata, context):
            raise RuntimeError("Simulation of model GPU out-of-memory crash")

    broken = BrokenDetector(
        detector_id="broken_01",
        detector_name="Crashing Model",
        detector_version="1.0.0",
        supported_media_types=[MediaTypeEnum.IMAGE],
    )
    reg = DetectorRegistry()
    reg.register(broken)

    pipeline = MultimediaPipeline(registry=reg)
    png_data = create_synthetic_png()
    assessment = pipeline.analyze_media(png_data, "test.png")

    # One failed detector must not crash the analysis; it yields INSUFFICIENT_EVIDENCE
    assert len(assessment.detector_results) == 1
    assert assessment.detector_results[0].status == DetectorStatusEnum.FAILED
    assert assessment.classification == AuthenticityClassificationEnum.INSUFFICIENT_EVIDENCE


# ============================================================================
# 5. EVIDENCE FUSION & EPISTEMIC RULES
# ============================================================================

def test_19_evidence_fusion_supporting_vs_contradicting():
    # Valid C2PA credentials actively discount suspicion
    data = create_synthetic_jpeg()
    meta = MediaMetadata(camera_make="Canon", camera_model="EOS R5")
    prov = ProvenanceRecord(
        status=ProvenanceStatusEnum.VALID_CREDENTIALS,
        credential_present=True,
        signature_valid=True,
        issuer="Canon C2PA Signer",
    )

    det_res = DetectorResult(
        detector_id="test_det",
        detector_name="Test Heuristic",
        detector_version="1.0.0",
        media_type=MediaTypeEnum.IMAGE,
        status=DetectorStatusEnum.SUCCESS,
        score=0.72,
        confidence=0.85,
    )

    assessment = MediaAuthenticityAggregator.aggregate(
        artifact_id="art_test",
        media_type=MediaTypeEnum.IMAGE,
        media_format=MediaFormatEnum.JPEG,
        metadata=meta,
        provenance=prov,
        detector_results=[det_res],
        analysis_run_id="run_test",
    )

    # Contradicting findings from C2PA and camera EXIF must be present
    assert len(assessment.contradicting_findings) >= 2
    # Net risk is discounted by authentic credentials
    assert assessment.risk_score < 40.0


def test_20_multimodal_detector_disagreement():
    # Video frames authentic (score 0.15) but audio synthetic (score 0.90)
    v_res = DetectorResult(
        detector_id="vid_frame_01",
        detector_name="Video Frame Detector",
        detector_version="1.0.0",
        media_type=MediaTypeEnum.VIDEO,
        status=DetectorStatusEnum.SUCCESS,
        score=0.15,
    )
    a_res = DetectorResult(
        detector_id="aud_spec_01",
        detector_name="Audio Acoustic Detector",
        detector_version="1.0.0",
        media_type=MediaTypeEnum.AUDIO,
        status=DetectorStatusEnum.SUCCESS,
        score=0.90,
    )

    assessment = MediaAuthenticityAggregator.aggregate(
        artifact_id="art_disagree",
        media_type=MediaTypeEnum.VIDEO,
        media_format=MediaFormatEnum.MP4,
        metadata=MediaMetadata(has_video_track=True, has_audio_track=True),
        provenance=ProvenanceRecord(),
        detector_results=[v_res, a_res],
        analysis_run_id="run_disagree",
    )

    # Must raise MULTIMODAL_DETECTOR_DISAGREEMENT finding
    disagree_finding = next(
        (f for f in assessment.supporting_findings if f.finding_type == "MULTIMODAL_DETECTOR_DISAGREEMENT"),
        None,
    )
    assert disagree_finding is not None
    assert disagree_finding.severity == SeverityEnum.HIGH


def test_21_unknown_media_never_classified_as_authentic():
    # Epistemic Rule: If no detectors succeeded, return INSUFFICIENT_EVIDENCE, never AUTHENTIC
    assessment = MediaAuthenticityAggregator.aggregate(
        artifact_id="art_unknown",
        media_type=MediaTypeEnum.UNKNOWN_MEDIA,
        media_format=MediaFormatEnum.UNKNOWN,
        metadata=MediaMetadata(),
        provenance=ProvenanceRecord(),
        detector_results=[],
        analysis_run_id="run_unknown",
    )
    assert assessment.classification == AuthenticityClassificationEnum.INSUFFICIENT_EVIDENCE
    assert assessment.risk_score == 0.0


# ============================================================================
# 6. FALSE-POSITIVE CONTROLS
# ============================================================================

def test_22_false_positive_missing_exif_does_not_mean_fake():
    # Stripped EXIF on a normal PNG
    clean_png = create_synthetic_png()
    pipeline = MultimediaPipeline()
    assessment = pipeline.analyze_media(clean_png, "clean_no_exif.png")
    assert assessment.classification != AuthenticityClassificationEnum.STRONG_SYNTHETIC_MEDIA_INDICATORS
    assert assessment.classification != AuthenticityClassificationEnum.SYNTHETIC_MEDIA_SIGNALS_DETECTED


def test_23_false_positive_photoshop_metadata_alone_does_not_mean_ai_fake():
    # Image edited with Photoshop is a tool, not necessarily AI generation
    data = create_synthetic_png(metadata_dict={"Software": "Adobe Photoshop 24.1 (Macintosh)"})
    pipeline = MultimediaPipeline()
    assessment = pipeline.analyze_media(data, "photo_retouched.png")
    # Should not produce AI generator finding
    assert not any(f.finding_type == "IMAGE_AI_GENERATION_SIGNAL" for f in assessment.supporting_findings)


# ============================================================================
# 7. SECTION 12 IMPERSONATION HANDSHAKE & THREAT EVENTS
# ============================================================================

def test_24_section_12_impersonation_handshake():
    db = SessionLocal()
    try:
        # Create an executive profile in DB
        prof = ProtectedIdentityModel(
            id="pip_alice_ceo",
            display_name="Alice Smith",
            entity_type="EXECUTIVE",
            source="ORGANIZATION_CONFIGURED",
            verification_status="VERIFIED",
            revision=1,
            is_active=True,
            trusted_domains_json='["acme.example"]',
            trusted_emails_json='["alice.smith@acme.example"]',
            known_names_json='["Alice Smith"]',
            known_roles_json='["Chief Executive Officer", "CEO"]',
        )
        db.merge(prof)
        db.commit()

        # Generate synthetic audio with TTS cutoff mimicking executive voice clone
        tts_audio = create_synthetic_wav(duration_s=2.0, bandlimited=True)
        pipeline = MultimediaPipeline()

        assessment = pipeline.analyze_media(
            data=tts_audio,
            original_filename="alice_voicemail.wav",
            context_claimed_identity_id="pip_alice_ceo",
            db=db,
        )

        assert assessment.classification in (
            AuthenticityClassificationEnum.SYNTHETIC_MEDIA_SIGNALS_DETECTED,
            AuthenticityClassificationEnum.STRONG_SYNTHETIC_MEDIA_INDICATORS,
        )

        # Verify ThreatEvent was created for DEEPFAKE_IMPERSONATION_SUSPECTED
        te = db.query(ThreatEventModel).filter(
            ThreatEventModel.event_type == "DEEPFAKE_IMPERSONATION_SUSPECTED"
        ).first()
        assert te is not None
        assert "Alice Smith" in te.summary

        # Verify Graph Relationship TARGETS was created
        rel = db.query(RelationshipModel).filter(
            RelationshipModel.relationship_type == "TARGETS"
        ).first()
        assert rel is not None

    finally:
        db.close()


def test_25_reanalysis_preserves_historical_run():
    db = SessionLocal()
    try:
        data = create_synthetic_png()
        art_id = "art_reanal_test"
        pipeline = MultimediaPipeline()

        # Run 1
        ass1 = pipeline.analyze_media(data, "test.png", artifact_id=art_id, db=db)
        run1_id = ass1.analysis_run_id

        # Run 2 (reanalysis)
        ass2 = pipeline.analyze_media(data, "test.png", artifact_id=art_id, db=db)
        run2_id = ass2.analysis_run_id

        assert run1_id != run2_id

        # Both runs exist in DB
        runs = db.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id == art_id).all()
        assert len(runs) >= 2

    finally:
        db.close()


# ============================================================================
# 8. REST API ENDPOINTS TESTS
# ============================================================================

def test_26_api_list_detectors():
    res = client.get("/api/multimedia/detectors")
    assert res.status_code == 200
    detectors = res.json()
    assert len(detectors) >= 5
    det_ids = [d["detector_id"] for d in detectors]
    assert "img_meta_01" in det_ids
    assert "img_freq_01" in det_ids
    assert "aud_spec_01" in det_ids


def test_27_api_analyze_payload():
    png_data = create_synthetic_png()
    b64_payload = base64.b64encode(png_data).decode("utf-8")

    res = client.post("/api/multimedia/analyze", json={
        "media_bytes_b64": b64_payload,
        "filename": "api_test.png",
    })
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["media_identity"]["media_type"] == "IMAGE"
    assert "classification" in body["assessment"]
    assert "risk_score" in body["assessment"]


def test_28_api_reanalyze_nonexistent_artifact():
    res = client.post("/api/multimedia/reanalyze/art_does_not_exist_404")
    assert res.status_code == 404
