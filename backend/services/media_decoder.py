"""Bounded local decoding. Original evidence is never rewritten."""
import io
import os
import subprocess
import tempfile
import wave
from pathlib import Path
from PIL import Image

MAX_INPUT = 50 * 1024 * 1024
TIMEOUT_SECONDS = 20
MAX_SECONDS = 30
MAX_FRAMES = 8
MAX_OUTPUT = 6 * 1024 * 1024


def decoder_executable():
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except (ImportError, RuntimeError):
        return None


def decode_media(data, media_type, media_format):
    """Return status, bounded analysis bytes/frames, verified sample metadata, limitations."""
    result = {'status': 'UNSUPPORTED_FORMAT', 'audio': None, 'frames': [], 'metadata': {}, 'limitations': []}
    if not data or len(data) > MAX_INPUT:
        result.update(status='INVALID_CONTENT', limitations=['Empty media or input exceeds the 50 MB limit.'])
        return result
    if media_type == 'IMAGE':
        try:
            with Image.open(io.BytesIO(data)) as image:
                if image.width * image.height > 16_000_000:
                    result.update(status='RESOURCE_LIMIT', limitations=['Image exceeds the 16 megapixel analysis limit.'])
                    return result
                image.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.load()
            result['status'] = 'COMPLETED'
        except Exception:
            result.update(status='INVALID_CONTENT', limitations=['Image could not be decoded.'])
        return result
    demuxers = {'WAV': 'wav', 'MP3': 'mp3', 'OGG': 'ogg', 'FLAC': 'flac', 'MP4': 'mov', 'MOV': 'mov', 'AVI': 'avi', 'WEBM': 'matroska'}
    if media_format not in demuxers:
        result['limitations'] = ['No supported media signature was identified.']
        return result
    executable = decoder_executable()
    if not executable:
        result.update(status='DECODER_UNAVAILABLE', limitations=['Install the imageio-ffmpeg backend dependency to decode this media.'])
        return result
    with tempfile.TemporaryDirectory(prefix='cyberguard-decode-') as directory:
        root = Path(directory)
        source = root / 'input.bin'
        source.write_bytes(data)
        command = [executable, '-nostdin', '-hide_banner', '-loglevel', 'error', '-xerror',
                   '-max_alloc', '67108864', '-threads', '1', '-filter_threads', '1',
                   '-protocol_whitelist', 'file', '-probesize', '1048576', '-analyzeduration', '2000000',
                   '-f', demuxers[media_format], '-i', str(source), '-t', str(MAX_SECONDS)]
        if media_type == 'AUDIO':
            output = root / 'audio.wav'
            command += ['-map', '0:a:0', '-vn', '-ac', '1', '-ar', '44100', '-c:a', 'pcm_s16le', '-fs', str(MAX_OUTPUT), str(output)]
        else:
            command += ['-map', '0:v:0', '-an', '-vf', 'fps=1,scale=320:320:force_original_aspect_ratio=decrease',
                        '-frames:v', str(MAX_FRAMES), '-threads', '1', str(root / 'frame-%02d.png')]
        try:
            completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS, check=False,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            if completed.returncode:
                result.update(status='INVALID_CONTENT', limitations=['The decoder rejected invalid, truncated, or unsupported codec content.'])
                return result
            if sum(p.stat().st_size for p in root.iterdir() if p != source) > MAX_OUTPUT:
                result.update(status='RESOURCE_LIMIT', limitations=['Decoded output exceeds the analysis limit.'])
                return result
            if media_type == 'AUDIO':
                audio = output.read_bytes()
                with wave.open(io.BytesIO(audio)) as wav:
                    duration = wav.getnframes() / wav.getframerate()
                    if wav.getnframes() < 512:
                        result.update(status='INSUFFICIENT_EVIDENCE', limitations=['Too few decoded audio samples for analysis.'])
                        return result
                    result['metadata'] = {'sample_rate': wav.getframerate(), 'channels': wav.getnchannels(), 'duration_seconds': duration}
                result['audio'] = audio
            else:
                result['frames'] = [(i, float(i), p.read_bytes()) for i, p in enumerate(sorted(root.glob('frame-*.png'))[:MAX_FRAMES])]
                if not result['frames']:
                    result.update(status='INSUFFICIENT_EVIDENCE', limitations=['No frames decoded in the bounded sampling interval.'])
                    return result
            if result['frames']:
                with Image.open(io.BytesIO(result['frames'][0][2])) as frame:
                    result['metadata'] = {'width': frame.width, 'height': frame.height, 'sampled_frame_count': len(result['frames']), 'sampling_rate_hz': 1}
            result.update(status='COMPLETED', limitations=['Heuristic checks only; no validated deepfake model. Analysis uses at most 30 seconds of audio or eight 320-pixel frames at one frame per second; sample metadata and frame timestamps describe decoded sampling output, not exact source-frame provenance or the entire original. Audio may be resampled; codec and resampling artifacts can affect spectral heuristics.'])
        except subprocess.TimeoutExpired:
            result.update(status='PROCESSING_TIMEOUT', limitations=['Media decoding exceeded the 20 second deadline.'])
        except OSError:
            result.update(status='DECODER_UNAVAILABLE', limitations=['Media decoder could not be started or its output could not be read.'])
        except (ValueError, wave.Error, EOFError):
            result.update(status='INVALID_CONTENT', limitations=['Decoded media content is invalid.'])
    return result
