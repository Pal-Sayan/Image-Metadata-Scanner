<div align="center">

# 🕵️ Enhanced Metadata Extractor

**A comprehensive metadata extraction tool for digital forensics, OSINT, and security assessments.**

[![Author](https://img.shields.io/badge/Author-Sayan%20Pal-blue?style=flat-square&logo=github)](https://github.com/Pal-Sayan)
[![Collaborator](https://img.shields.io/badge/Collaborator-Soumit%20Santra-blue?style=flat-square&logo=github)](https://github.com/Soumit-Santra)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-3.0.0-22c55e?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-f97316?style=flat-square)](LICENSE)

</div>

---

## 📖 Overview

**Enhanced Metadata Extractor** is a powerful command-line and interactive tool that extracts every layer of metadata from a wide range of file types. It is designed for digital forensics investigators, OSINT analysts, and security professionals who need deep, reliable, and auditable metadata extraction.

It supports **ExifTool integration**, **parallel directory scanning**, **forensic case tracking**, **anomaly/steganography detection**, and output in JSON, HTML, and CSV formats.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔬 **ExifTool Integration** | 10x more metadata via ExifTool; falls back to Python stack gracefully |
| 🧲 **libmagic File Detection** | Accurate MIME type and true format detection, independent of file extension |
| 📷 **Image EXIF + GPS** | Camera make/model, lens, aperture, ISO, shutter speed, focal length, GPS coordinates + Google Maps link |
| 📄 **Document Metadata** | PDF author, creation date, encryption status; DOCX author, revision history, keywords |
| 🎵 **Audio / Video** | ID3 tags, bitrate, sample rate, duration; video streams via ffprobe |
| 📦 **Archive Analysis** | ZIP/JAR/APK file listings, compression ratios, CRC checksums |
| ⚙️ **PE Executable** | PE headers, imported DLLs, sections, version info for `.exe` / `.dll` |
| 💽 **Forensic Disk Images** | E01, DD/Raw, and AFF4 support via pytsk3/pyewf — partition listing and filesystem walk |
| 🔐 **File Hashes** | MD5, SHA1, SHA256 for every file |
| ⚠️ **Anomaly Detection** | Shannon entropy analysis, JPEG/PNG trailing data detection (steganography flags) |
| 🗂️ **Forensic Case Tracking** | Case IDs, examiner system info, UTC timestamps, structured JSON logs |
| ⚡ **Parallel Scanning** | Multi-threaded directory scanning with configurable worker count and progress bar |
| 📊 **Multiple Output Formats** | JSON (structured), HTML (visual report), CSV (spreadsheet) |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Pal-Sayan/enhanced-metadata-extractor.git
cd enhanced-metadata-extractor
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. (Recommended) Install ExifTool

ExifTool dramatically increases metadata coverage. Download from [https://exiftool.org](https://exiftool.org) and ensure it is available in your system `PATH`.

### 4. Run

```bash
# Interactive menu mode
python main_enhanced.py

# Single file (command-line)
python main_enhanced.py photo.jpg -v

# Directory scan
python main_enhanced.py -d /path/to/folder -r --workers 8
```

---

## 💻 Usage

### Interactive Mode

Running without arguments launches a full interactive menu:

```bash
python main_enhanced.py
```

Menu options include:
- Extract metadata from a single file
- Scan a directory (non-recursive or recursive)
- Forensic mode with case ID and log file
- Disk image analysis (E01, DD, AFF4)
- System capability checker
- Supported file types reference

### Command-Line Mode

```bash
python main_enhanced.py <input> [options]
```

| Option | Description |
|---|---|
| `input` | File or directory path |
| `-o`, `--output` | Output file (`.json`, `.html`, `.csv`) |
| `-f`, `--format` | Explicitly set output format |
| `-d`, `--directory` | Treat input as a directory |
| `-r`, `--recursive` | Recurse into subdirectories |
| `-v`, `--verbose` | Include full ExifTool output |
| `--workers N` | Number of parallel threads (default: 4) |
| `--case-id ID` | Assign a forensic case ID |
| `--log FILE` | Write structured log to file |

### Examples

```bash
# Single file, verbose output
python main_enhanced.py image.jpg -v

# Parallel recursive directory scan, save as HTML report
python main_enhanced.py -d ./evidence -r --workers 8 -o report.html

# Forensic mode with case tracking and JSON output
python main_enhanced.py evidence.pdf --case-id CASE-2024-001 --log case.log -o output.json

# Save CSV for spreadsheet analysis
python main_enhanced.py -d ./samples -o results.csv
```

---

## 📋 Sample Output

```
════════════════════════════════════════════════════════════
  FORENSIC INFORMATION
════════════════════════════════════════════════════════════
  Case ID        CASE-2024-001
  Tool           Enhanced Metadata Extractor v3.0.0
  Extraction UTC 2024-08-15T10:23:44Z
  Examiner OS    Linux 6.5.0

════════════════════════════════════════════════════════════
  FILE INFORMATION
════════════════════════════════════════════════════════════
  Filename       DSC_0042.jpg
  File Size      4.2 MB
  MD5            a1b2c3d4e5f6...
  SHA256         9f8e7d6c5b4a...
  MIME Type      image/jpeg
  Entropy        7.21

════════════════════════════════════════════════════════════
  EXIF DATA  (camera / capture)
════════════════════════════════════════════════════════════
  Make           NIKON CORPORATION
  Model          NIKON D750
  LensModel      24-70mm f/2.8
  ExposureTime   1/500
  FNumber        2.8
  ISO            400
  FocalLength    50.0 mm

════════════════════════════════════════════════════════════
  GPS / LOCATION
════════════════════════════════════════════════════════════
  Latitude       40.7128
  Longitude      -74.006
  Google Maps    https://maps.google.com/?q=40.7128,-74.006
```

---

## 📦 Requirements

### Python Libraries

| Package | Version | Purpose |
|---|---|---|
| [Pillow](https://python-pillow.org/) | `>= 10.0.0` | Image reading, EXIF, GPS |
| [hachoir](https://hachoir.readthedocs.io/) | `>= 3.0.0` | Robust fallback metadata parser |
| [PyPDF2](https://pypdf2.readthedocs.io/) | `>= 3.0.0` | PDF metadata |
| [python-docx](https://python-docx.readthedocs.io/) | `>= 0.8.11` | DOCX metadata |
| [mutagen](https://mutagen.readthedocs.io/) | `>= 1.46` | Audio/video tags |
| [pefile](https://github.com/erocarrera/pefile) | `>= 2023.2.7` | PE executable analysis |
| [python-magic](https://github.com/ahupp/python-magic) | `>= 0.4.27` | MIME/file type detection |
| [colorama](https://github.com/tartley/colorama) | `>= 0.4.6` | Coloured terminal output |
| [tqdm](https://tqdm.github.io/) | `>= 4.66` | Progress bars |

Install all at once:

```bash
pip install -r requirements.txt
```

### Optional External Tools

| Tool | Purpose | Install |
|---|---|---|
| [ExifTool](https://exiftool.org/) | Deep metadata extraction (highly recommended) | [exiftool.org](https://exiftool.org) |
| [ffprobe](https://ffmpeg.org/) | Video stream metadata | [ffmpeg.org](https://ffmpeg.org) |
| pytsk3 + pyewf | Forensic disk image support | `pip install pytsk3 pyewf` |

---

## 🗂️ Supported File Types

| Category | Formats | Extracted Data |
|---|---|---|
| **Images** | `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.webp`, `.heic` | EXIF, GPS, camera info, dimensions |
| **RAW Photos** | `.cr2`, `.nef`, `.arw`, `.dng`, `.orf` | Full EXIF via ExifTool/exifread |
| **Documents** | `.pdf`, `.docx` | Author, dates, revision history, encryption status |
| **Audio** | `.mp3`, `.flac`, `.m4a`, `.ogg`, `.wav` | ID3 tags, bitrate, sample rate, duration |
| **Video** | `.mp4`, `.avi`, `.mkv`, `.mov`, `.wmv` | Codec, resolution, bitrate, streams (requires ffprobe) |
| **Archives** | `.zip`, `.jar`, `.apk` | File list, compression ratios, CRC checksums |
| **Executables** | `.exe`, `.dll` | PE headers, imports, sections, version info |
| **Disk Images** | `.e01`, `.dd`, `.img`, `.iso`, `.aff4` | Partition table, filesystem walk, file timestamps |
| **Any / Unknown** | `*` | File hashes, MIME type, entropy, timestamps |

---

## 🔬 Forensic Features

### Case Tracking
Every extraction can be tagged with a **case ID** and logged to a structured JSON log file, recording:
- Examiner system info (OS, Python version, machine)
- Tool name and version
- UTC and local extraction timestamps
- Available library capabilities

### Anomaly & Steganography Detection
The tool automatically flags:
- **High Shannon entropy** on non-compressed file types — possible encryption or packing
- **JPEG trailing data** after the `FFD9` End-of-Image marker (>4KB, non-padding)
- **PNG trailing data** after the `IEND` chunk (>4KB, non-padding)

### Parallel Directory Scanning
Use `--workers N` to scan large evidence directories efficiently using multi-threading, with a live progress bar and per-file error tracking.

---

## 🧩 Project Structure

```
enhanced-metadata-extractor/
├── main_enhanced.py         # Main script (all logic)
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

---

## ⚠️ Ethical Use

This tool is intended for **legal and authorized use only**:

- Only analyze files and systems you have explicit permission to examine
- Respect applicable privacy laws and data protection regulations
- Do not use for unauthorized surveillance, data theft, or malicious purposes

---

## 🤝 Contributing

Contributions are welcome! To get started:

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
