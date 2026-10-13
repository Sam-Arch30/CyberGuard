"""Generate safe synthetic upload fixtures. No downloads of user/private evidence."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import csv, io, json, hashlib, math, os, struct, subprocess, sys, tarfile, wave, zipfile
from PIL import Image, ImageDraw
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parents[1] / 'samples'
ROOT.mkdir(exist_ok=True)
records=[]
def record(path, expected, screen, note=''):
    records.append({'file':path.relative_to(ROOT).as_posix(),'extension':path.suffix,'expected':expected,'screen':screen,'note':note,'size_bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
def write(folder,name,content,expected,screen,note=''):
    path=ROOT/folder/name;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(content if isinstance(content,bytes) else content.encode('utf-8'))
    record(path,expected,screen,note);return path

for name,subject,sender,reply,body in [
 ('benign-meeting.eml','Project meeting reminder','team@example.test','team@example.test','The project meeting is at 10 AM. No sign-in or payment is required.'),
 ('suspicious-credential-request.eml','URGENT: Verify your account now','security@account-verification.example','collector@untrusted.example','Your account will be suspended. Verify your password at https://account-verification.example/login immediately.'),
 ('suspicious-payment-request.eml','Confidential: urgent payment','finance@lookalike-example.test','payments@untrusted.example','Please send the urgent wire transfer today. Do not contact anyone else. Reply with the payment confirmation.')]:
    content=f'From: Example Team <{sender}>\r\nTo: analyst@example.test\r\nReply-To: {reply}\r\nReturn-Path: <{sender}>\r\nSubject: {subject}\r\nDate: Mon, 12 Oct 2026 09:00:00 +0000\r\nMessage-ID: <{name}@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n'
    write('01-email',name,content,'EMAIL','Phishing & email','Synthetic; expected findings are signals, not guaranteed verdicts.')

for name,body in [('benign-note.txt','CyberGuard synthetic document. Meeting notes only. No links or credentials.'),('suspicious-message.txt','URGENT! Your account is blocked. Verify your password at https://login-check.example/login now.')]:
    write('02-documents',name,body,'TEXT','Detection Center')
write('02-documents','sample.html','<!doctype html><html><head><title>Synthetic sample</title></head><body><h1>CyberGuard test document</h1><p>Static content only; no scripts or external assets.</p></body></html>','TEXT / FILE','Files & attachments')
write('02-documents','sample.rtf',r'{\rtf1\ansi CyberGuard synthetic RTF sample. No executable content.}','TEXT / FILE','Files & attachments')
write('02-documents','sample.xml','<?xml version="1.0"?><sample><purpose>CyberGuard testing</purpose><synthetic>true</synthetic></sample>','TEXT / FILE','Detection Center')
write('02-documents','sample.md','# Synthetic test document\n\nThis file contains no private investigation data.\n','TEXT','Detection Center')
folder=ROOT/'02-documents';folder.mkdir(exist_ok=True)
pdf=folder/'benign-document.pdf';page=canvas.Canvas(str(pdf));page.setTitle('CyberGuard synthetic sample');page.setFont('Helvetica-Bold',20);page.drawString(60,760,'CyberGuard test document');page.setFont('Helvetica',11)
for index,line in enumerate(['Synthetic fixture for document upload testing.','No scripts, embedded attachments or external resources.','This is sample evidence, not a real incident.','Expected behavior: read PDF metadata and preserve its hash.']):page.drawString(60,715-index*25,line)
page.showPage();page.save();record(pdf,'FILE / PDF','Files & attachments')

image=Image.new('RGB',(640,360),'#f4f5f0');draw=ImageDraw.Draw(image);draw.rectangle((24,24,616,336),outline='#789266',width=3);draw.text((48,70),'CyberGuard - SYNTHETIC IMAGE',fill='#253529');draw.text((48,110),'No real person. No deepfake ground truth.',fill='#253529')
for extension,fmt in [('png','PNG'),('jpg','JPEG'),('webp','WEBP'),('gif','GIF'),('bmp','BMP')]:
    path=ROOT/'03-images'/('synthetic-card.'+extension);path.parent.mkdir(exist_ok=True);image.save(path,format=fmt);record(path,'IMAGE','Detection Center','Generated graphic; not a deepfake accuracy sample.')
write('03-images','synthetic-diagram.svg','<svg xmlns="http://www.w3.org/2000/svg" width="640" height="180"><rect width="640" height="180" fill="#f4f5f0"/><text x="30" y="90" fill="#253529">CyberGuard synthetic SVG - no scripts</text></svg>','TEXT / FILE','Files & attachments','SVG classification may differ from raster images.')

wav=ROOT/'04-audio'/'synthetic-tone.wav';wav.parent.mkdir(exist_ok=True)
with wave.open(str(wav),'wb') as audio:
    audio.setnchannels(1);audio.setsampwidth(2);audio.setframerate(16000)
    audio.writeframes(b''.join(struct.pack('<h',int(3000*math.sin(2*math.pi*440*i/16000))) for i in range(32000)))
record(wav,'AUDIO','Detection Center','Two-second generated tone; no speech or cloned voice.')
tools=Path(os.environ.get('TEMP',''))/'cyberguard-fixture-tools'
if tools.exists():sys.path.insert(0,str(tools))
import imageio_ffmpeg
ffmpeg=imageio_ffmpeg.get_ffmpeg_exe()
def convert(arguments,path,expected,note):
    path.parent.mkdir(exist_ok=True)
    subprocess.run([ffmpeg,'-hide_banner','-loglevel','error','-y',*arguments,str(path)],check=True,timeout=45,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    record(path,expected,'Detection Center',note)
for extension,codec in [('mp3','libmp3lame'),('ogg','libvorbis'),('flac','flac')]:
    convert(['-i',str(wav),'-c:a',codec],ROOT/'04-audio'/('synthetic-tone.'+extension),'AUDIO','Generated tone; codec support may vary by analyzer.')
for extension,codec in [('mp4','libx264'),('mov','libx264'),('avi','mpeg4'),('webm','libvpx')]:
    convert(['-f','lavfi','-i','testsrc=size=320x180:rate=12','-t','2','-an','-c:v',codec,'-pix_fmt','yuv420p'],ROOT/'05-video'/('synthetic-color-bars.'+extension),'VIDEO','Valid two-second generated video; no faces, not a labelled deepfake.')

start=datetime(2026,10,12,9,tzinfo=timezone.utc)
normal=[{'timestamp':(start+timedelta(minutes=i)).isoformat(),'user':'analyst@example.test','status':'success','ip':'192.0.2.10','mfa_result':'success'} for i in range(5)]
spray=[{'timestamp':(start+timedelta(seconds=i*4)).isoformat(),'user':f'user{i%8}@example.test','status':'failure','ip':'198.51.100.20','failure_reason':'invalid_password'} for i in range(24)]
for name,events in [('normal-auth.json',normal),('password-spray.json',spray)]:write('06-logs',name,json.dumps(events,indent=2),'AUTH_LOG (focused route)','Account & access','Upload to the authentication screen; universal detection may classify JSON arrays as text.')
write('06-logs','authentication-events.jsonl','\n'.join(json.dumps(event) for event in spray)+'\n','TEXT / LOG','Account & access','JSONL support depends on the chosen log parser.')
stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=['timestamp','src_ip','dst_ip','src_port','dst_port','protocol','bytes_sent']);writer.writeheader()
for i in range(5):writer.writerow({'timestamp':(start+timedelta(seconds=i*20)).isoformat(),'src_ip':'192.0.2.10','dst_ip':'203.0.113.15','src_port':50000+i,'dst_port':443,'protocol':'TCP','bytes_sent':1024*(i+1)})
write('06-logs','network-connections.csv',stream.getvalue(),'TEXT / NETWORK_LOG','Network telemetry','Documentation IPs only; no real traffic captured.')
write('06-logs','sample-access.log','192.0.2.10 - - [12/Oct/2026:09:00:00 +0000] "GET /login HTTP/1.1" 200 512\n198.51.100.20 - - [12/Oct/2026:09:00:04 +0000] "POST /api/auth HTTP/1.1" 401 64\n','TEXT / LOG','Detection Center')
write('06-logs','api-events.json',json.dumps([{'timestamp':(start+timedelta(seconds=i)).isoformat(),'method':'GET','path':'/api/users','status_code':403,'source_ip':'198.51.100.20'} for i in range(12)],indent=2),'API_LOG (focused route)','API log analyzer','Synthetic repeated denied requests.')
write('07-identity','trusted-profile.json',json.dumps({'display_name':'Example Finance','trusted_domains':['example.test'],'trusted_sender_addresses':['finance@example.test']},indent=2),'PROFILE REFERENCE','Identity impersonation','Use these values in the protected profile form; not an automatic profile importer.')
write('07-identity','identity-claim.txt','Protected profile: Example Finance\nClaimed name: Example Finance\nSender: finance@lookalike-example.test\nReply-to: collector@untrusted.example\nSubject: Urgent payment approval\nMessage: Send the transfer immediately and keep this confidential.\n','MANUAL FORM REFERENCE','Identity impersonation')

folder=ROOT/'08-archives';folder.mkdir(exist_ok=True)
archive=folder/'benign-bundle.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as zipped:
    zipped.writestr('README.txt','Safe synthetic archive. No executables or traversal paths.')
    zipped.write(ROOT/'02-documents'/'benign-note.txt',arcname='documents/benign-note.txt')
record(archive,'FILE / ARCHIVE','Files & attachments')
archive=folder/'benign-bundle.tar.gz'
with tarfile.open(archive,'w:gz') as bundled:bundled.add(ROOT/'02-documents'/'benign-note.txt',arcname='benign-note.txt')
record(archive,'FILE / ARCHIVE','Files & attachments')
write('09-binary','benign-data.bin',b'CYBERGUARD_SYNTHETIC_BINARY\x00'+bytes(range(256))*4,'FILE','Files & attachments','Arbitrary inert bytes; not executable or malware.')
write('10-invalid','empty.txt',b'','EXPECT REJECTION','Detection Center','Intentionally empty.')
write('10-invalid','malformed.json','{"events": [','EXPECT ERROR / TEXT FALLBACK','Account & access','Intentionally invalid JSON.')
write('10-invalid','broken.pdf',b'%PDF-1.7\nintentionally incomplete','EXPECT PARSER LIMITATION','Files & attachments','Not a valid PDF.')
write('10-invalid','broken.mp4',b'not a video','EXPECT FORMAT LIMITATION','Detection Center','MP4 extension with invalid bytes.')
write('10-invalid','jpeg-with-pdf-extension.pdf',(ROOT/'03-images'/'synthetic-card.jpg').read_bytes(),'EXPECT MIME MISMATCH','Detection Center','Valid JPEG deliberately named PDF.')

(ROOT/'manifest.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(records[0]));writer.writeheader();writer.writerows(records);(ROOT/'manifest.csv').write_text(stream.getvalue(),encoding='utf-8')
(ROOT/'README.md').write_text("""# CyberGuard safe testing samples

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
""",encoding='utf-8')
print(f'Created {len(records)} fixtures in {ROOT}')
