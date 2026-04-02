<div align="center">

# 🕵️ ForensiScan

**Advanced File Intelligence & Forensic Analysis Tool**

[![Author](https://img.shields.io/badge/Author-Sayan%20Pal-blue?style=flat-square&logo=github)](https://github.com/Pal-Sayan)
[![Collaborator](https://img.shields.io/badge/Collaborator-Soumit%20Santra-blue?style=flat-square&logo=github)](https://github.com/Soumit-Santra)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-6.0.0-22c55e?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-f97316?style=flat-square)](LICENSE)

</div>

---

## 📖 Overview

**ForensiScan v6** is a comprehensive digital forensics and file intelligence platform for investigators, OSINT analysts, and security professionals. It combines deep metadata extraction, malware threat scoring, YARA scanning, timeline reconstruction, and a full-featured GUI — all while operating with **streaming memory efficiency** so even multi-gigabyte files never blow your RAM.

v6 ships two interfaces from the same script:

- **CLI** — interactive menu or fully scriptable argument mode
- **GUI** — a themed Tkinter dashboard with seven tabs, animated gauges, a timeline graph, a multi-file risk table, and live search/filter

---

## ✨ What's New in v6

| Area | Change |
|---|---|
| **Streaming memory** | Entropy computed in O(256 bytes) RAM; hashes in a single streaming pass; YARA scans via `mmap` (zero-copy); pattern search uses a sliding window so matches across chunk boundaries are never missed |
| **YARA threat engine** | Built-in ruleset covers EICAR, UPX packing, PowerShell download cradles, PHP webshells, Base64-encoded PE, reverse shells, and crypto-miners; pluggable via `yara-python` |
| **Threat Intelligence module** | Risk score 0–100, five severity bands (CLEAN / LOW / MEDIUM / HIGH / CRITICAL), IOC list, packer detection, PE timestamp anomaly checks, known-malicious hash lookup |
| **Chain of Custody** | Cryptographically chained audit log (SHA-256 linked entries), integrity verification, JSON persistence, GUI tab |
| **Timeline Reconstructor** | Merges filesystem MAC times, EXIF dates, document properties, PE compile timestamps, ExifTool fields into a single sorted timeline |
| **GUI — Timeline Graph tab** | Canvas-based lane diagram; density heat-band; zoom slider (0.3×–5×); hover tooltips; click-to-detail side panel |
| **GUI — Multi-File Risk Dashboard** | Sortable table for batch directory scans; live search, risk-level filter, file-type filter; per-row colour coding; quick-detail pane; click bubbles to single-file tabs |
| **GUI — Risk Heatmap tab** | Animated bar chart of score contributors; 15-cell indicator matrix; risk-reason log |
| **5 GUI themes** | Cyber Dark · Arctic · Obsidian · Matrix · Rose Gold — live-switchable via theme picker |
| **Disk image support** | E01 / EWF, DD/raw, ISO via `pytsk3` + `pyewf`; partition listing, filesystem walk, sample file roster |

---

## ✨ Full Feature Set

| Feature | Details |
|---|---|
| 🔬 **ExifTool integration** | Subprocess wrapper; 10× more metadata fields; graceful fallback |
| 🧲 **libmagic file detection** | True MIME type and format detection independent of file extension |
| 📷 **Image EXIF + GPS** | Camera make/model, lens, aperture, ISO, shutter, focal length, GPS coords + Google Maps URL |
| 📄 **Document metadata** | PDF author/dates/encryption; DOCX author/revision/last-modified-by |
| 🎵 **Audio / video** | ID3 tags, bitrate, sample rate, duration; video streams via ffprobe |
| 📦 **Archive analysis** | ZIP / JAR / APK file listings, compression ratios, CRC checksums |
| ⚙️ **PE executable** | PE headers, imported DLLs, section table, compile timestamp |
| 💽 **Disk images** | E01, DD/Raw, ISO, AFF4 — partition table, filesystem walk |
| 🔐 **File hashes** | MD5, SHA-1, SHA-256 — all in a single streaming pass |
| 📡 **YARA scanning** | mmap-based zero-copy scan; 7 built-in rules; 256 MB file cap |
| ⚠️ **Anomaly detection** | Shannon entropy (O(256 B) RAM), JPEG/PNG trailing-data steganography flags |
| 🧮 **Threat scoring** | 0–100 composite score; packer signatures, suspicious pattern search, known-hash lookup |
| 🗃️ **Chain of Custody** | SHA-256 chained entries, per-event integrity verification, JSON export |
| 🕒 **Timeline reconstruction** | Merged & sorted events from filesystem, EXIF, documents, PE, ExifTool |
| ⚡ **Parallel scanning** | `ThreadPoolExecutor`-backed directory scanner; configurable worker count; tqdm progress bar |
| 📊 **Output formats** | JSON (full), HTML (visual report), CSV (spreadsheet-ready) |
| 🖥️ **GUI** | Seven-tab Tkinter dashboard; animated gauge; 5 themes; live search/filter; export buttons |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Pal-Sayan/forensiscan.git
cd forensiscan
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. (Recommended) Install ExifTool

ExifTool dramatically increases metadata coverage.

```bash
# Debian / Ubuntu
sudo apt install libimage-exiftool-perl

# macOS
brew install exiftool

# Windows — download exiftool.exe from https://exiftool.org and place in PATH
```

### 4. Run

```bash
# Startup prompt — choose CLI or GUI
python forensiscan.py

# Single file (CLI, skip prompt)
python forensiscan.py photo.jpg -v

# Directory scan
python forensiscan.py -d /path/to/evidence -r --workers 8 -o report.html
```

---

## 💻 Usage

### Startup Prompt

Running without arguments shows a mode selector:

```
[1]  CLI  – Terminal / interactive menu
[2]  GUI  – Graphical dashboard with all v6 features
```

### Interactive CLI Menu

```
1. Extract metadata – single file
2. Process directory (non-recursive)
3. Process directory (recursive)
4. Forensic mode – single file + case tracking + CoC
5. Forensic mode – directory scan
6. Analyse disk image (E01 / DD / AFF4)
7. System capabilities
8. Supported file types
9. About
0. Exit
```

### Command-Line Mode

```bash
python forensiscan.py <input> [options]
```

| Option | Description |
|---|---|
| `input` | File or directory path |
| `-o`, `--output` | Output file (`.json`, `.html`, `.csv`) |
| `-f`, `--format` | Explicitly set output format |
| `-d`, `--directory` | Treat input as a directory |
| `-r`, `--recursive` | Recurse into subdirectories |
| `-v`, `--verbose` | Include full ExifTool output in console |
| `--workers N` | Parallel threads for directory scan (default: 4) |
| `--case-id ID` | Assign a forensic case ID |
| `--examiner NAME` | Record examiner name in CoC log |
| `--log FILE` | Write structured JSON log to file |
| `--coc FILE` | Persist Chain of Custody to file |

### Examples

```bash
# Single file, verbose
python forensiscan.py image.jpg -v

# Recursive directory scan → HTML report
python forensiscan.py -d ./evidence -r --workers 8 -o report.html

# Forensic mode with case ID and CoC file
python forensiscan.py evidence.pdf \
    --case-id CASE-2024-001 \
    --examiner "Jane Smith" \
    --log case.log \
    --coc custody.json \
    -o output.json

# CSV for bulk spreadsheet analysis
python forensiscan.py -d ./samples -r -o results.csv
```

---

## 🖥️ GUI Tabs

| Tab | Description |
|---|---|
| **Dashboard** | Six metric cards, animated risk gauge (0–100), file info pane, IOC list |
| **Timeline Graph** | Canvas lane diagram — one lane per category, density heat-band, zoom 0.3×–5×, hover tooltips, click-to-detail |
| **Multi-File Risk** | Sortable table for batch scans; live search, risk-level filter, file-type filter; click row → populates other tabs |
| **Risk Heatmap** | Animated contributor bar chart, 15-cell boolean indicator matrix, risk-reason log |
| **YARA** | Rule-match table sorted by severity; click row → offset/string detail |
| **Chain of Custody** | Canvas audit trail with linked-hash display; integrity badge |
| **Raw JSON** | Full scrollable JSON output for the current file |

---

## 📋 Sample Console Output

```
════════════════════════════════════════════════════════════
  FORENSISCAN v6.0.0 — EXTRACTION REPORT
════════════════════════════════════════════════════════════

[FILE INFORMATION]
  Filename       : DSC_0042.jpg
  File Size      : 4.21 MB
  Extension      : .jpg
  Created Time   : 2024-03-15T08:22:11
  Modified Time  : 2024-03-15T08:22:11
  Permissions    : 644

[HASHES]
  MD5    : a1b2c3d4e5f67890...
  SHA1   : 1a2b3c4d5e6f7890...
  SHA256 : 9f8e7d6c5b4a3b2c...

[THREAT INTELLIGENCE]
  Risk:   5/100  [██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  LOW
  ⚑  GPS coordinates found – location privacy leak

[TIMELINE — 5 events]
  2024-03-15T08:22:11  [filesystem  ]  Filesystem          File created
  2024-03-15T08:22:11  [exif        ]  EXIF                Photo taken
  ...

[CHAIN OF CUSTODY]
  Record: <uuid>  |  Events: 4  |  Integrity: ✓ INTACT
════════════════════════════════════════════════════════════
```

---

## 📦 Requirements

### Python Libraries

| Package | Version | Purpose |
|---|---|---|
| [Pillow](https://python-pillow.org/) | `>= 10.0.0` | Image reading, EXIF, GPS |
| [hachoir](https://hachoir.readthedocs.io/) | `>= 3.0.0` | Deep fallback metadata parser |
| [PyPDF2](https://pypdf2.readthedocs.io/) | `>= 3.0.0` | PDF metadata extraction |
| [python-docx](https://python-docx.readthedocs.io/) | `>= 0.8.11` | DOCX core properties |
| [mutagen](https://mutagen.readthedocs.io/) | `>= 1.46.0` | Audio tag extraction |
| [pefile](https://github.com/erocarrera/pefile) | `>= 2023.2.7` | PE executable analysis |
| [python-magic](https://github.com/ahupp/python-magic) | `>= 0.4.27` | MIME / file-type detection |
| [yara-python](https://yara.readthedocs.io/) | `>= 4.3.0` | YARA malware rule scanning *(v6 NEW)* |
| [colorama](https://github.com/tartley/colorama) | `>= 0.4.6` | Coloured terminal output |
| [tqdm](https://tqdm.github.io/) | `>= 4.66.0` | Directory-scan progress bars |

Install all at once:

```bash
pip install -r requirements.txt
```

### Optional / Advanced

| Package | Purpose | Install |
|---|---|---|
| `pytsk3` | Disk image filesystem walk | `pip install pytsk3` |
| `pyewf` | E01 / EWF image support | `pip install pyewf` |
| `tkinter` | GUI (stdlib on Windows/macOS) | `sudo apt install python3-tk` |

### External Binaries

| Tool | Purpose | Install |
|---|---|---|
| [ExifTool](https://exiftool.org/) | Deep metadata (highly recommended) | `apt install libimage-exiftool-perl` / `brew install exiftool` |
| [ffprobe](https://ffmpeg.org/) | Video stream metadata | `apt install ffmpeg` / `brew install ffmpeg` |

---

## 🗂️ Supported File Types

| Category | Formats | Extracted Data |
|---|---|---|
| **Images** | `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.webp`, `.heic` | EXIF, GPS, camera info, dimensions, steganography flags |
| **Documents** | `.pdf`, `.docx` | Author, dates, revision, encryption status |
| **Audio** | `.mp3`, `.flac`, `.m4a`, `.ogg`, `.wav` | ID3/Vorbis tags, bitrate, sample rate, duration |
| **Video** | `.mp4`, `.avi`, `.mkv`, `.mov`, `.wmv` | Codec, resolution, bitrate, streams (requires ffprobe) |
| **Archives** | `.zip`, `.jar`, `.apk` | File listing, compression ratios, CRC checksums |
| **Executables** | `.exe`, `.dll` | PE headers, imports, sections, compile timestamp |
| **Disk Images** | `.e01`, `.dd`, `.img`, `.iso`, `.aff4` | Partition table, filesystem walk, file timestamps |
| **Any / Unknown** | `*` | MD5/SHA1/SHA256, MIME type, entropy, timestamps, YARA scan |

---

## 🔬 Forensic Deep-Dive

### Streaming Memory Architecture

ForensiScan v6 never loads an entire file into RAM for core operations:

- **Hashing** — single streaming pass updating MD5, SHA-1, SHA-256 simultaneously
- **Entropy** — only a 256-element frequency table is kept; RAM usage is O(1)
- **YARA** — files above 4 MB are scanned via `mmap` (zero-copy); hard cap at 256 MB
- **Pattern search** — sliding-window across 64 KB chunks; cross-boundary matches always caught
- **Steganography check** — only the last 8–16 KB of the file is read via `seek(-n, 2)`

### Threat Intelligence & Scoring

Risk score is a 0–100 composite built from:

| Contributor | Max bump |
|---|---|
| Known-malicious hash match | +100 |
| YARA critical rule | +60 |
| YARA high rule | +40 |
| YARA medium rule | +25 |
| Packer/protector detected | +30 |
| Very high entropy (non-compressed) | +30 |
| Suspicious byte patterns | +20 |
| PE timestamp anomaly | +20–35 |
| Suspicious filesystem flags | +25 |
| GPS data present | +5 |

### Built-in YARA Rules

| Rule | Severity |
|---|---|
| `Detect_EICAR` | LOW |
| `Detect_UPX_Packed` | MEDIUM |
| `Detect_Crypto_Mining` | MEDIUM |
| `Detect_PowerShell_Download` | HIGH |
| `Detect_Base64_PE` | HIGH |
| `Detect_PHP_Webshell` | CRITICAL |
| `Detect_Reverse_Shell` | CRITICAL |

### Chain of Custody

Each CoC record is a SHA-256 chained event log. Every entry hashes itself together with the previous entry's hash, making tampering detectable even after the fact. The GUI displays each event in a visual audit trail with hash prefixes and an integrity badge.

### Timeline Reconstruction

Sources merged into a single chronological event list:

- Filesystem: created, modified, accessed (MAC times)
- EXIF: DateTimeOriginal, DateTime
- DOCX: core properties created/modified
- PDF: CreationDate, ModDate
- PE: FILE_HEADER.TimeDateStamp
- ExifTool: FileModifyDate

---

## 🧩 Project Structure

```
forensiscan/
├── forensiscan.py       # All-in-one script (CLI + GUI)
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## ⚠️ Ethical Use

This tool is intended for **legal and authorised use only**:

- Analyse only files and systems you have explicit permission to examine
- Respect applicable privacy laws and data-protection regulations
- Do not use for unauthorised surveillance, data theft, or malicious purposes

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to your branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with ❤️ and Python &nbsp;·&nbsp; **[Sayan Pal](https://github.com/Pal-Sayan)** &nbsp;·&nbsp; **[Soumit Santra](https://github.com/Soumit-Santra)**

</div>