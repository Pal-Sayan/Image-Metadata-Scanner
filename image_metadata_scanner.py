#!/usr/bin/env python3
"""
Image Metadata Scanner
Scans and displays metadata from image files regardless of extension.
Supports: JPEG, PNG, GIF, BMP, TIFF, WEBP, ICO, RAW formats, HEIC, and more.

Author : Sayan Pal (https://github.com/Pal-Sayan)
"""

import sys
import os
import struct
from pathlib import Path
from datetime import datetime

# ── dependency check ──────────────────────────────────────────────────────────
def check_and_install(package, import_name=None):
    import importlib
    name = import_name or package
    try:
        return importlib.import_module(name)
    except ImportError:
        print(f"[INFO] Installing '{package}'...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "-q"])
        return importlib.import_module(name)

PIL_Image   = check_and_install("Pillow",       "PIL.Image")
PIL_ExifTags= check_and_install("Pillow",       "PIL.ExifTags")
exifread    = check_and_install("exifread")

from PIL import Image, ExifTags
from PIL.ExifTags import TAGS, GPSTAGS
import exifread

# ── helpers ───────────────────────────────────────────────────────────────────

SEPARATOR = "─" * 60

def section(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print('═' * 60)

def row(key: str, value):
    if value not in (None, "", b"", {}, []):
        print(f"  {key:<35} {value}")

def bytes_to_human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def dms_to_decimal(dms, ref: str) -> float | None:
    """Convert GPS DMS tuple to decimal degrees."""
    try:
        d, m, s = [float(x.num) / float(x.den) for x in dms]
        decimal = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 7)
    except Exception:
        return None

def decode_exif_value(tag_name: str, value):
    """Best-effort decoding of an EXIF value to something printable."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8").strip("\x00")
        except Exception:
            return value.hex()
    return value

# ── metadata extraction ───────────────────────────────────────────────────────

def get_file_info(path: Path) -> dict:
    stat = path.stat()
    return {
        "File Name"        : path.name,
        "File Path"        : str(path.resolve()),
        "File Size"        : bytes_to_human(stat.st_size),
        "Raw Size (bytes)" : stat.st_size,
        "Extension"        : path.suffix.lower() or "(none)",
        "Created"          : datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "Modified"         : datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
    }

def get_pil_info(path: Path) -> dict:
    """Basic image properties from Pillow."""
    info = {}
    try:
        with Image.open(path) as img:
            info["Format"]          = img.format or "Unknown"
            info["Mode"]            = img.mode
            info["Width (px)"]      = img.width
            info["Height (px)"]     = img.height
            info["Megapixels"]      = f"{img.width * img.height / 1_000_000:.2f} MP"
            info["Color Depth"]     = f"{len(img.getbands()) * 8} bit"

            # DPI / resolution
            dpi = img.info.get("dpi")
            if dpi:
                info["DPI"]         = f"{dpi[0]:.0f} × {dpi[1]:.0f}"

            # Palette
            if img.mode == "P":
                info["Palette"]     = "Yes"

            # Animation
            if hasattr(img, "n_frames"):
                info["Frame Count"] = img.n_frames

            # ICC profile
            if "icc_profile" in img.info:
                info["ICC Profile"] = f"Present ({len(img.info['icc_profile'])} bytes)"

            # Format-specific
            for key in ("compression", "photometric", "software", "description",
                        "comment", "exif", "jfif", "jfif_version", "loop"):
                val = img.info.get(key)
                if val is not None:
                    info[key.capitalize()] = val
    except Exception as e:
        info["PIL Error"] = str(e)
    return info

def get_exif_pil(path: Path) -> dict:
    """EXIF data via Pillow (works best for JPEG/TIFF)."""
    exif_data = {}
    try:
        with Image.open(path) as img:
            raw = img._getexif()  # type: ignore[attr-defined]
            if raw:
                for tag_id, value in raw.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    exif_data[tag] = decode_exif_value(tag, value)
    except Exception:
        pass
    return exif_data

def get_exif_exifread(path: Path) -> dict:
    """EXIF data via exifread (wider format support)."""
    tags = {}
    try:
        with open(path, "rb") as f:
            raw = exifread.process_file(f, details=True, strict=False)
        for k, v in raw.items():
            tags[k] = str(v)
    except Exception:
        pass
    return tags

def get_gps_info(exif_dict: dict) -> dict | None:
    """Extract and convert GPS info from PIL EXIF dictionary."""
    gps_tag_id = next((i for i, n in TAGS.items() if n == "GPSInfo"), None)
    if gps_tag_id is None:
        return None
    try:
        with Image.open("__dummy__"):
            pass
    except Exception:
        pass

    gps_raw = exif_dict.get("GPSInfo")
    if not gps_raw or not isinstance(gps_raw, dict):
        return None

    gps = {}
    for key, val in gps_raw.items():
        gps[GPSTAGS.get(key, key)] = val

    result = {}
    lat  = dms_to_decimal(gps.get("GPSLatitude"),  gps.get("GPSLatitudeRef",  "N"))
    lon  = dms_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef", "E"))
    alt  = gps.get("GPSAltitude")

    if lat is not None:
        result["Latitude"]  = lat
    if lon is not None:
        result["Longitude"] = lon
    if lat and lon:
        result["Google Maps"] = f"https://maps.google.com/?q={lat},{lon}"
    if alt:
        try:
            result["Altitude (m)"] = float(alt.num) / float(alt.den)
        except Exception:
            result["Altitude"]     = str(alt)
    return result or None

def get_gps_from_pil(path: Path) -> dict | None:
    """Wrapper: open the image and pull GPS."""
    try:
        with Image.open(path) as img:
            raw_exif = img._getexif()  # type: ignore[attr-defined]
            if not raw_exif:
                return None
            exif_full = {TAGS.get(k, k): v for k, v in raw_exif.items()}
            return get_gps_info({**raw_exif, **exif_full,
                                 "GPSInfo": raw_exif.get(
                                     next((i for i, n in TAGS.items()
                                           if n == "GPSInfo"), None))})
    except Exception:
        return None

def detect_real_format(path: Path) -> str:
    """Peek at magic bytes to identify the real format regardless of extension."""
    signatures = {
        b"\xff\xd8\xff"       : "JPEG",
        b"\x89PNG\r\n\x1a\n" : "PNG",
        b"GIF87a"             : "GIF",
        b"GIF89a"             : "GIF",
        b"BM"                 : "BMP",
        b"II\x2a\x00"        : "TIFF (little-endian)",
        b"MM\x00\x2a"        : "TIFF (big-endian)",
        b"RIFF"               : "RIFF container (WEBP/AVI/…)",
        b"\x00\x00\x01\x00"  : "ICO",
        b"\x00\x00\x02\x00"  : "CUR",
        b"8BPS"               : "Photoshop PSD",
        b"\x1a\x45\xdf\xa3"  : "WebM/MKV",
    }
    try:
        with open(path, "rb") as f:
            header = f.read(12)
        for sig, name in signatures.items():
            if header.startswith(sig):
                return name
        # WEBP specific check inside RIFF
        if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
            return "WEBP"
    except Exception:
        pass
    return "Unknown"

# ── pretty printer ─────────────────────────────────────────────────────────────

INTERESTING_EXIF = {
    "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
    "DateTimeDigitized", "ExifImageWidth", "ExifImageHeight",
    "Orientation", "XResolution", "YResolution", "ResolutionUnit",
    "Flash", "FocalLength", "FocalLengthIn35mmFilm", "ExposureTime",
    "FNumber", "ISOSpeedRatings", "ExposureProgram", "MeteringMode",
    "WhiteBalance", "LightSource", "SceneCaptureType", "Copyright",
    "Artist", "ImageDescription", "UserComment", "SubjectDistance",
    "DigitalZoomRatio", "Contrast", "Saturation", "Sharpness",
    "ColorSpace", "ExifVersion", "FlashPixVersion", "ComponentsConfiguration",
    "CompressedBitsPerPixel", "BrightnessValue", "ExposureBiasValue",
    "MaxApertureValue", "SubjectDistanceRange", "LensModel", "LensMake",
    "LensSpecification",
}

def print_metadata(path: Path):
    section(f"FILE INFORMATION  ·  {path.name}")
    finfo = get_file_info(path)
    for k, v in finfo.items():
        row(k, v)

    real_fmt = detect_real_format(path)
    row("Detected Format (magic bytes)", real_fmt)

    section("IMAGE PROPERTIES")
    pinfo = get_pil_info(path)
    for k, v in pinfo.items():
        row(k, v)

    # ── EXIF ──────────────────────────────────────────────────────────────────
    exif_pil = get_exif_pil(path)

    if exif_pil:
        section("EXIF DATA  (camera / capture)")
        printed = set()
        for tag in sorted(INTERESTING_EXIF):
            if tag in exif_pil:
                row(tag, exif_pil[tag])
                printed.add(tag)

        # Any remaining EXIF tags not in the curated list
        extras = {k: v for k, v in exif_pil.items()
                  if k not in printed and k != "GPSInfo" and k != "MakerNote"}
        if extras:
            section("EXIF DATA  (additional tags)")
            for k, v in sorted(extras.items()):
                row(k, v)

    # ── GPS ───────────────────────────────────────────────────────────────────
    gps = get_gps_from_pil(path)
    if gps:
        section("GPS / LOCATION")
        for k, v in gps.items():
            row(k, v)

    # ── Extended via exifread ─────────────────────────────────────────────────
    exr = get_exif_exifread(path)
    if exr:
        # Show tags not already covered by PIL
        new_tags = {k: v for k, v in exr.items()
                    if k.split(" ")[-1] not in exif_pil}
        if new_tags:
            section("EXTENDED EXIF  (exifread)")
            for k, v in sorted(new_tags.items()):
                row(k, v)

    if not exif_pil and not exr:
        print("\n  [No EXIF metadata found in this file]")

    print(f"\n{'═' * 60}\n")


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python image_metadata_scanner.py <image_file> [image2 ...]")
        print("\nExample:")
        print("  python image_metadata_scanner.py photo.jpg")
        print("  python image_metadata_scanner.py img.png raw_file.cr2 scan.tiff")
        sys.exit(1)

    for arg in sys.argv[1:]:
        path = Path(arg)
        if not path.exists():
            print(f"\n[ERROR] File not found: {arg}")
            continue
        if not path.is_file():
            print(f"\n[ERROR] Not a file: {arg}")
            continue
        try:
            print_metadata(path)
        except Exception as e:
            print(f"\n[ERROR] Could not read '{arg}': {e}")

if __name__ == "__main__":
    main()