"""Render compact, source-grounded technical flowcharts; no generated artwork."""
from pathlib import Path
from html import escape
from PIL import Image, ImageDraw, ImageFont
import json
import shutil
import zipfile

OUT = Path(__file__).resolve().parent
DOWNLOAD = Path(r'C:\Users\bipin\Downloads\CyberGuard-Additional-Flowcharts')
DOWNLOAD.mkdir(parents=True, exist_ok=True)
CHARTS = [('05-file-attachments', 'File & Attachment Detection Flow', ['Upload file / attachment\nBounded input; reject empty/truncated PDF', 'FileIdentityAnalyzer + FilenameSecurityAnalyzer\nHashes, magic/MIME, Unicode and extensions', 'Run matching static analyzer\nPDF / Office / PE / script / ZIP checks\nInspect entropy and archive entries', 'FileIOCAnalyzer + FileReputationAnalyzer\nExtract references; query file-hash reputation', 'FileClassificationService.classify\nCombine findings, hash reputation and type', 'Persist original / derived evidence\nReturn classification, risk and findings'], 'Focused file API; hash no-match does not establish safety.'), ('06-network-anomalies', 'Network Anomaly Detection Flow', ['Submit network event batch\nProvider-specific adapter normalization', 'Deduplicate; sort by timestamp\nBuild device baseline profiles', 'Check external-destination threat intelligence\nUse available configured lookup results', 'Run network rule engines\nConnection scans, periodicity, DNS patterns\nTransfer/exfiltration and destination anomalies', 'NetworkPatternAggregator\nCombine findings; calculate overall risk', 'Persist events, findings and device profiles\nReturn network classification and risk'], 'Analyzes submitted telemetry; not continuous packet interception.'), ('07-api-abuse', 'API Abuse Detection Flow', ['Submit API request telemetry\nAdapter normalization with secret redaction', 'Deduplicate; sort by timestamp\nBuild account baseline profiles', 'Run API abuse rule engines\nBursts, enumeration, authentication failures\nMethod/privilege, session and scraping signals', 'Check cross-module correlations\nExisting authentication and network records', 'APIPatternAggregator.aggregate\nCombine findings; score abuse hypotheses', 'Persist normalized events and findings\nReturn abuse classification and risk'], 'Rules operate on available telemetry and configuration.'), ('08-audio-spectral', 'Audio Spectral Heuristic Flow', ['Upload audio\nIdentify signature; enforce bounded input', 'decode_media: local FFmpeg\nUp to 30 s; mono PCM WAV at 44.1 kHz', 'AudioSpectralAcousticDetector\nRead samples; select channel; normalize amplitude', 'SciPy real FFT\nEnergy above 8 kHz; spectral flatness', 'Apply abrupt-band-cutoff rule\nSample rate >= 22050 Hz\nHigh-frequency energy ratio < 0.001', 'Return heuristic evidence and limitations\nCalibrated authenticity confidence unavailable'], 'Not a trained voice-clone detector; no verified real/fake verdict.')]

W, H, SCALE = 640, 870, 2
BOX_X, BOX_W, BOX_H, GAP, TOP = 42, 556, 100, 25, 105
FONT_ROOT = Path(r'C:\Windows\Fonts')
def font(size, bold=False):
    return ImageFont.truetype(str(FONT_ROOT / ('arialbd.ttf' if bold else 'arial.ttf')), size * SCALE)

def render(name, title, steps, note):
    img = Image.new('RGB', (W*SCALE, H*SCALE), 'white')
    d = ImageDraw.Draw(img)
    d.text((W*SCALE/2, 35*SCALE), title, fill='#111111', font=font(22, True), anchor='mt')
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
           '<rect width="100%" height="100%" fill="white"/>',
           '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#111"/></marker></defs>',
           f'<text x="{W/2}" y="56" text-anchor="middle" font-family="Arial,sans-serif" font-size="22" font-weight="bold">{escape(title)}</text>']
    for i, step in enumerate(steps):
        y = TOP + i*(BOX_H+GAP)
        fill = '#EFEDF4' if i == len(steps)-1 else '#FFF9EC'
        d.rectangle((BOX_X*SCALE,y*SCALE,(BOX_X+BOX_W)*SCALE,(y+BOX_H)*SCALE),fill=fill,outline='#333333',width=2)
        svg.append(f'<rect x="{BOX_X}" y="{y}" width="{BOX_W}" height="{BOX_H}" fill="{fill}" stroke="#333" stroke-width="1"/>')
        lines=step.split('\n'); line_height=22; start=y+(BOX_H-line_height*len(lines))/2
        for j,line in enumerate(lines):
            d.text((W*SCALE/2,(start+j*line_height)*SCALE),line,fill='#111111',font=font(17,j==0),anchor='mt')
            svg.append(f'<text x="{W/2}" y="{start+j*line_height+16}" text-anchor="middle" font-family="Arial,sans-serif" font-size="17" font-weight="{"bold" if j==0 else "normal"}">{escape(line)}</text>')
        if i < len(steps)-1:
            x=W*SCALE/2; y1=(y+BOX_H+3)*SCALE; y2=(y+BOX_H+GAP-5)*SCALE
            d.line((x,y1,x,y2),fill='#111111',width=3)
            d.polygon([(x,y2+5*SCALE),(x-4*SCALE,y2-2*SCALE),(x+4*SCALE,y2-2*SCALE)],fill='#111111')
            svg.append(f'<line x1="{W/2}" y1="{y+BOX_H+3}" x2="{W/2}" y2="{y+BOX_H+GAP-3}" stroke="#111" stroke-width="1.5" marker-end="url(#arrow)"/>')
    d.text((W*SCALE/2,838*SCALE),note,fill='#555555',font=font(12),anchor='mt')
    svg.append(f'<text x="{W/2}" y="851" text-anchor="middle" font-family="Arial,sans-serif" font-size="12" fill="#555">{escape(note)}</text></svg>')
    img.save(OUT/f'{name}.png'); (OUT/f'{name}.svg').write_text('\n'.join(svg),encoding='utf-8')
    return img

images=[render(*chart) for chart in CHARTS]
page=Image.new('RGB',(W*SCALE*2,H*SCALE*2),'white')
for i,img in enumerate(images): page.paste(img,((i%2)*W*SCALE,(i//2)*H*SCALE))
page.save(OUT/'additional-four-2x2.png')
(OUT/'diagram-steps.json').write_text(json.dumps(CHARTS,indent=2),encoding='utf-8')
for path in OUT.iterdir():
    if path.is_file() and path.suffix in ('.png','.svg','.md','.json'): shutil.copy2(path,DOWNLOAD/path.name)
with zipfile.ZipFile(DOWNLOAD.parent/'CyberGuard-Additional-Flowcharts.zip','w',zipfile.ZIP_DEFLATED) as z:
    for path in DOWNLOAD.iterdir():
        if path.is_file():z.write(path,path.name)
print(DOWNLOAD)
