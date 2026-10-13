# CyberGuard safe testing samples

All files are generated synthetic fixtures. None contains real private evidence,
live malware, executable scripts, cloned speech or labelled deepfakes. URLs use
reserved example/test domains and IPs use documentation ranges.

| Folder | Contents | Where to test |
| --- | --- | --- |
| 01-email | Benign and suspicious .eml messages | Phishing & email |
| 02-documents | PDF, TXT, HTML, RTF, XML, Markdown | Detection Center / Files |
| 03-images | PNG, JPG, WEBP, GIF, BMP, SVG | Detection Center |
| 04-audio | Valid WAV, MP3, OGG, FLAC generated tone | Detection Center |
| 05-video | Valid MP4, MOV, AVI, WEBM color bars | Detection Center |
| 06-logs | JSON, JSONL, CSV and LOG telemetry | Focused authentication/network screens |
| 07-identity | Trusted profile and suspicious identity claim | Fill the identity form |
| 08-archives | Safe ZIP and TAR.GZ | Files & attachments |
| 09-binary | Inert .bin bytes | Files & attachments |
| 10-invalid | Empty, malformed, truncated and mismatched formats | Error handling |

Start with benign-meeting.eml, benign-document.pdf, synthetic-card.png,
synthetic-tone.wav and synthetic-color-bars.mp4. Then compare suspicious email and
password-spray.json. Use the invalid folder last. A test passes when errors are
clear and data stays intact; it need not classify every suspicious example as high risk.

JSON array logs belong in their focused log upload view. Universal ingestion can
classify them as plain text. Office/Outlook files are not included because creating
fake .docx/.xlsx/.msg files by renaming text would not test valid format support.

Media ingestion and metadata checks are not validated deepfake detection. Generated
color bars and tones cannot measure deepfake accuracy. Some codecs/extensions are
only partly supported; consult each result's capability warnings.

manifest.csv and manifest.json list file sizes, SHA-256 hashes, expected handling and
suggested screens. Do not upload these manifests as attack evidence. No live workspace
has been populated with these samples automatically.
