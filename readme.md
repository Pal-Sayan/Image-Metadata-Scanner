<div align="center">

# 🔍 Image Metadata Scanner

**Scan, extract, and display complete metadata from any image — regardless of file extension.**

[![Author](https://img.shields.io/badge/Author-Sayan%20Pal-blue?style=flat-square&logo=github)](https://github.com/Pal-Sayan)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Pillow](https://img.shields.io/badge/Pillow-10.0%2B-f97316?style=flat-square)](https://python-pillow.org/)
[![exifread](https://img.shields.io/badge/exifread-3.0%2B-a855f7?style=flat-square)](https://pypi.org/project/exifread/)

</div>

---

## 📖 Overview

**Image Metadata Scanner** is a lightweight yet powerful command-line tool that extracts every layer of metadata from image files — EXIF camera data, GPS coordinates, color profiles, pixel dimensions, magic-byte format detection, and more.

It works on **any file extension** (even misnamed or extensionless files) by using magic-byte detection to identify the true format, then applying dual-library extraction for the most complete metadata possible.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🖼️ **Any Extension** | Scans `.jpg`, `.png`, `.tiff`, `.webp`, `.bmp`, `.gif`, `.ico`, `.psd`, `.cr2`, `.nef`, `.arw`, and more |
| 🧲 **Magic Byte Detection** | Identifies the real file format from binary headers, ignoring the extension |
| 📷 **Full EXIF Support** | Camera make/model, lens, aperture, shutter speed, ISO, focal length, flash, white balance |
| 🌍 **GPS Extraction** | Latitude, longitude, altitude, and a one-click Google Maps link |
| 🎨 **Image Properties** | Dimensions, megapixels, DPI, color mode, bit depth, frame count, ICC profile |
| 📁 **File Info** | File size, creation time, modification time, path |
| 🔬 **Dual-Engine EXIF** | Uses both **Pillow** and **exifread** to maximize tag coverage, especially for RAW formats |
| 🔧 **Auto-Install Deps** | Missing packages are installed automatically on first run |
| 📦 **Zero Config** | No setup, no config files — just run it |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Pal-Sayan/image-metadata-scanner.git
cd image-metadata-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
python image_metadata_scanner.py photo.jpg
```

---

## 💻 Usage

```bash
python image_metadata_scanner.py <image_file> [image2 ...]
```

### Single file
```bash
python image_metadata_scanner.py photo.jpg
```

### Multiple files at once
```bash
python image_metadata_scanner.py img.png scan.tiff raw.cr2
```

### Works even with wrong or missing extensions
```bash
python image_metadata_scanner.py mystery_file
python image_metadata_scanner.py image.wrongext
```

---

## 📋 Sample Output

```
════════════════════════════════════════════════════════════
  FILE INFORMATION  ·  DSC_0042.jpg
════════════════════════════════════════════════════════════
  File Name                           DSC_0042.jpg
  File Path                           /home/user/photos/DSC_0042.jpg
  File Size                           4.2 MB
  Extension                           .jpg
  Detected Format (magic bytes)       JPEG
  Created                             2024-08-15 10:23:44
  Modified                            2024-08-15 10:23:44

════════════════════════════════════════════════════════════
  IMAGE PROPERTIES
════════════════════════════════════════════════════════════
  Format                              JPEG
  Mode                                RGB
  Width (px)                          5472
  Height (px)                         3648
  Megapixels                          19.96 MP
  Color Depth                         24 bit
  DPI                                 72 × 72

════════════════════════════════════════════════════════════
  EXIF DATA  (camera / capture)
════════════════════════════════════════════════════════════
  Make                                NIKON CORPORATION
  Model                               NIKON D750
  LensModel                           24-70mm f/2.8
  DateTime                            2024:08:15 10:23:44
  ExposureTime                        1/500
  FNumber                             2.8
  ISOSpeedRatings                     400
  FocalLength                         50.0
  Flash                               Flash did not fire

════════════════════════════════════════════════════════════
  GPS / LOCATION
════════════════════════════════════════════════════════════
  Latitude                            40.7128
  Longitude                           -74.006
  Google Maps                         https://maps.google.com/?q=40.7128,-74.006
```

---

## 📦 Requirements

| Package | Version | Purpose |
|---|---|---|
| [Pillow](https://python-pillow.org/) | `>= 10.0.0` | Image reading, EXIF, GPS, image properties |
| [exifread](https://pypi.org/project/exifread/) | `>= 3.0.0` | Extended EXIF for RAW and exotic formats |

All other modules (`sys`, `os`, `struct`, `pathlib`, `datetime`) are part of Python's standard library.

Install everything at once:
```bash
pip install -r requirements.txt
```

---

## 🗂️ Supported Formats

| Format | Extension(s) | Notes |
|---|---|---|
| JPEG | `.jpg`, `.jpeg` | Full EXIF + GPS |
| PNG | `.png` | Image properties, embedded metadata |
| GIF | `.gif` | Frame count, loop info |
| BMP | `.bmp` | Basic properties |
| TIFF | `.tiff`, `.tif` | Full EXIF support |
| WEBP | `.webp` | Properties + EXIF if present |
| ICO / CUR | `.ico`, `.cur` | Basic info |
| Photoshop | `.psd` | Layer/mode info |
| RAW | `.cr2`, `.nef`, `.arw`, `.dng`, `.orf`, etc. | Extended EXIF via exifread |
| HEIC | `.heic` | Requires `pillow-heif` plugin |
| Any | *(any / none)* | Magic-byte detection always runs |

---

## 🧩 Project Structure

```
image-metadata-scanner/
├── image_metadata_scanner.py   # Main script
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

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

Made with ❤️ and Python &nbsp;·&nbsp; **[Sayan Pal](https://github.com/Pal-Sayan)**

</div>