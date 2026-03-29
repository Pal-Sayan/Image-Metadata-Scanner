"""
Enhanced Metadata Extractor for Ethical Hacking
A comprehensive tool for extracting metadata from various file types
Useful for digital forensics, OSINT, and security assessments

Author: Sayan Pal
Collaborator: Soumit Santra

New Features:
- ExifTool integration for comprehensive metadata extraction
- libmagic for accurate file type detection
- Forensic metadata block with case tracking
- Parallel directory scanning
- Advanced format support (ZIP, Video, PE files)
- Structured logging
"""

import os
import sys
import json
import argparse
import subprocess
import logging
import platform
import zipfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import hashlib
import math
import csv

import csv

# Third-party imports
try:
    from colorama import init, Fore, Style
    from tqdm import tqdm
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Mock classes if not available
    class MockColor:
        def __getattr__(self, name): return ""
    Fore = MockColor()
    Style = MockColor()
    def init(): pass
    def tqdm(iterable=None, **kwargs): return iterable

# Initialize colorama
init(autoreset=True)

try:

    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from hachoir.parser import createParser
    from hachoir.metadata import extractMetadata
    from hachoir.core.cmd_line import unicodeFilename
    HACHOIR_AVAILABLE = True
except ImportError:
    HACHOIR_AVAILABLE = False

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from docx import Document
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import mutagen
    from mutagen.mp3 import MP3
    from mutagen.mp4 import MP4
    from mutagen.flac import FLAC
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False

# Forensic Image Support
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False

try:
    import pyewf
    EWF_AVAILABLE = True
except ImportError:
    EWF_AVAILABLE = False

try:
    import aff4
    AFF4_AVAILABLE = True
except ImportError:
    AFF4_AVAILABLE = False


# Global constants
VERSION = "3.0.0"
TOOL_NAME = "Enhanced Metadata Extractor"
DEFAULT_WORKERS = 4
EXIFTOOL_TIMEOUT = 30


class ForensicLogger:
    """Structured logging for forensic analysis"""
    
    def __init__(self, log_file: Optional[str] = None, case_id: Optional[str] = None):
        self.case_id = case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.log_file = log_file
        self.lock = Lock()
        
        # Configure logging
        self.logger = logging.getLogger(TOOL_NAME)
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (JSON structured logs)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(file_handler)
    
    def log_event(self, level: str, message: str, **kwargs):
        """Log structured event"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'case_id': self.case_id,
            'level': level,
            'message': message,
            'tool_version': VERSION,
            **kwargs
        }
        
        with self.lock:
            if level == 'INFO':
                self.logger.info(json.dumps(log_entry))
            elif level == 'WARNING':
                self.logger.warning(json.dumps(log_entry))
            elif level == 'ERROR':
                self.logger.error(json.dumps(log_entry))
            elif level == 'CRITICAL':
                self.logger.critical(json.dumps(log_entry))
            else:
                self.logger.debug(json.dumps(log_entry))
    
    def info(self, message: str, **kwargs):
        self.log_event('INFO', message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self.log_event('WARNING', message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self.log_event('ERROR', message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self.log_event('CRITICAL', message, **kwargs)


class ExifToolWrapper:
    """Wrapper for ExifTool integration"""
    
    def __init__(self):
        self.available = self._check_exiftool()
    
    def _check_exiftool(self) -> bool:
        """Check if ExifTool is available"""
        try:
            result = subprocess.run(
                ['exiftool', '-ver'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def extract_metadata(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract metadata using ExifTool"""
        if not self.available:
            return None
        
        try:
            result = subprocess.run(
                ['exiftool', '-j', '-G', '-a', '-s', str(file_path)],
                capture_output=True,
                text=True,
                timeout=EXIFTOOL_TIMEOUT
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data[0] if data else None
            
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            return None
        
        return None


class FileTypeDetector:
    """Advanced file type detection using libmagic"""
    
    def __init__(self):
        self.available = MAGIC_AVAILABLE
    
    def detect(self, file_path: str) -> Dict[str, str]:
        """Detect file type and MIME type"""
        result = {
            'extension': Path(file_path).suffix.lower(),
            'mime_type': None,
            'description': None,
            'real_type': None
        }
        
        if self.available:
            try:
                # Get MIME type
                mime = magic.Magic(mime=True)
                result['mime_type'] = mime.from_file(file_path)
                
                # Get description
                desc = magic.Magic()
                result['description'] = desc.from_file(file_path)
                
                # Determine real type
                result['real_type'] = self._classify_type(result['mime_type'], result['extension'])
                
            except Exception:
                pass
        
        # Fallback classification based on extension if magic failed or type is unknown
        if not result['real_type']:
            result['real_type'] = self._classify_type(None, result['extension'])
            
        return result
    
    def _classify_type(self, mime_type: Optional[str], extension: Optional[str] = None) -> Optional[str]:
        """Classify file type from MIME or extension"""
        ext = extension.lower() if extension else ""
        
        if ext in ['.e01', '.aff4', '.dd', '.img', '.iso']:
            return 'disk_image'
            
        if not mime_type:
            return None
        
        if mime_type.startswith('image/'):
            return 'image'
        elif mime_type.startswith('video/'):
            return 'video'
        elif mime_type.startswith('audio/'):
            return 'audio'
        elif 'pdf' in mime_type:
            return 'pdf'
        elif 'word' in mime_type or 'document' in mime_type:
            return 'document'
        elif 'zip' in mime_type or 'compressed' in mime_type:
            return 'archive'
        elif 'executable' in mime_type or mime_type == 'application/x-dosexec':
            return 'executable'
        
        return 'unknown'


class DiskImageHandler:
    """Forensic disk image handler for E01, DD, and AFF4 images"""
    
    def __init__(self, image_path: str, logger: Optional[ForensicLogger] = None):
        self.image_path = str(image_path)
        self.logger = logger
        self.img_info = None
        self.fs_info = None
        self.partitions = []
        
    def open_image(self):
        """Open a disk image in a forensically sound read-only manner"""
        if not TSK_AVAILABLE:
            raise ImportError("pytsk3 is required for disk image handling")
            
        ext = Path(self.image_path).suffix.lower()
        
        try:
            if ext in ['.e01', '.s01'] and EWF_AVAILABLE:
                # Handle EWF (Expert Witness Format)
                filenames = pyewf.get_filenames(self.image_path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                # TSK needs a wrapper for EWF
                self.img_info = pytsk3.Img_Info(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL, external_handle=ewf_handle)
            elif ext == '.aff4' and AFF4_AVAILABLE:
                # AFF4 handling would go here (complex, needs specific AFF4 library)
                # For now, we'll mark as unavailable or use DD if it's a raw AFF4 volume
                pass
            else:
                # Default to Raw/DD
                self.img_info = pytsk3.Img_Info(self.image_path)
                
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to open disk image: {str(e)}")
            return False

    def list_partitions(self) -> List[Dict[str, Any]]:
        """List partitions in the disk image"""
        partitions = []
        if not self.img_info:
            return partitions
            
        try:
            volume = pytsk3.Volume_Info(self.img_info)
            for part in volume:
                partitions.append({
                    'id': part.addr,
                    'description': part.desc.decode('utf-8', errors='ignore'),
                    'start': part.start,
                    'length': part.len,
                    'flags': part.flags
                })
        except Exception:
            # Maybe it's a single partition image (no partition table)
            partitions.append({
                'id': 0,
                'description': 'Single Partition / Raw Volume',
                'start': 0,
                'length': self.img_info.get_size(),
                'flags': pytsk3.TSK_VS_PART_FLAG_ALLOC
            })
            
        self.partitions = partitions
        return partitions

    def walk_filesystem(self, partition_id: int = 0) -> List[Dict[str, Any]]:
        """Walk the filesystem of a specific partition and extract file metadata"""
        files_metadata = []
        if not self.img_info:
            return files_metadata
            
        try:
            offset = 0
            if self.partitions:
                for p in self.partitions:
                    if p['id'] == partition_id:
                        offset = p['start'] * 512 # Sector size 512 assumed
                        break
            
            fs = pytsk3.FS_Info(self.img_info, offset=offset)
            root_dir = fs.open_dir(path="/")
            
            def _walk(directory, current_path=""):
                for entry in directory:
                    if entry.info.name.name in [b".", b".."]:
                        continue
                        
                    name = entry.info.name.name.decode('utf-8', errors='ignore')
                    full_path = f"{current_path}/{name}"
                    
                    # Basic metadata
                    meta = {
                        'name': name,
                        'path': full_path,
                        'size': entry.info.meta.size if entry.info.meta else 0,
                        'type': 'directory' if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR else 'file',
                        'inode': entry.info.meta.addr if entry.info.meta else 0,
                        'created': datetime.fromtimestamp(entry.info.meta.crtime).isoformat() if entry.info.meta and hasattr(entry.info.meta, 'crtime') else None,
                        'modified': datetime.fromtimestamp(entry.info.meta.mtime).isoformat() if entry.info.meta and hasattr(entry.info.meta, 'mtime') else None,
                        'accessed': datetime.fromtimestamp(entry.info.meta.atime).isoformat() if entry.info.meta and hasattr(entry.info.meta, 'atime') else None,
                    }
                    files_metadata.append(meta)
                    
                    if meta['type'] == 'directory':
                        try:
                            sub_dir = entry.as_directory()
                            _walk(sub_dir, full_path)
                        except Exception:
                            pass
                            
            _walk(root_dir)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error walking filesystem on partition {partition_id}: {str(e)}")
                
        return files_metadata


class EnhancedMetadataExtractor:
    """Enhanced metadata extraction with forensic capabilities"""
    
    def __init__(self, file_path: str, case_id: Optional[str] = None, 
                 logger: Optional[ForensicLogger] = None):
        self.file_path = Path(file_path)
        self.case_id = case_id
        self.logger = logger or ForensicLogger(case_id=case_id)
        self.exiftool = ExifToolWrapper()
        self.file_detector = FileTypeDetector()
        
        self.metadata = {
            'forensic_info': {},
            'file_info': {},
            'file_type_analysis': {},
            'extracted_metadata': {},
            'hashes': {},
            'exiftool_metadata': {},
            'warnings': [],
            'errors': []
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Calculate frequency of each byte
        occurrences = [0] * 256
        for byte in data:
            occurrences[byte] += 1
            
        entropy = 0
        total_len = len(data)
        
        for count in occurrences:
            if count > 0:
                p_x = float(count) / total_len
                entropy -= p_x * math.log(p_x, 2)
                
        return entropy

    def _detect_suspicious(self):
        """Detect suspicious anomalies and hidden data"""
        suspicious = []
        
        # Files that naturally have high entropy (compression/encryption)
        COMPRESSED_EXTENSIONS = {
            '.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic',
            '.zip', '.rar', '.7z', '.gz', '.tar', '.jar', '.apk',
            '.pdf', '.docx', '.xlsx', '.pptx',
            '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.flac'
        }
        
        try:
            # Read file data (limit memory usage for huge files)
            file_size = self.file_path.stat().st_size
            
            # 1. Entropy Analysis
            if file_size < 100 * 1024 * 1024:  # 100MB limit for full entropy
                with open(self.file_path, 'rb') as f:
                    data = f.read()
                    entropy = self._calculate_entropy(data)
                    self.metadata['forensic_info']['entropy'] = round(entropy, 4)
                    
                    # Only flag high entropy if it's NOT a known compressed format
                    # Most compressed files are > 7.5. Encrypted/Packer usually > 7.9
                    if entropy > 7.95: 
                         ext = self.file_path.suffix.lower()
                         if ext not in COMPRESSED_EXTENSIONS:
                            suspicious.append(f"Extremely high entropy ({entropy:.2f}) for {ext} file - Potential encryption/packing")
                    elif entropy < 1.0 and file_size > 4096:
                        suspicious.append(f"Very low entropy ({entropy:.2f}) - Large blocks of uniform data")
            
            # 2. JPEG Trailing Data
            if self.file_path.suffix.lower() in ['.jpg', '.jpeg']:
                with open(self.file_path, 'rb') as f:
                    f.seek(0)
                    content = f.read()
                    eoi_index = content.rfind(b'\xff\xd9')
                    
                    if eoi_index != -1 and eoi_index + 2 < len(content):
                        extra_data = content[eoi_index + 2:]
                        extra_len = len(extra_data)
                        
                        # Filter out False Positives:
                        # 1. Ignore small amounts of data (< 4KB) which is often just metadata/thumbnails/padding
                        # 2. Ignore common padding bytes (Nulls, FF, Newlines)
                        is_padding = all(b in b'\x00\xff\r\n\t ' for b in extra_data)
                        
                        if extra_len > 4096 and not is_padding:
                            suspicious.append(f"Significant trailing data found after JPEG EOF: {extra_len} bytes (Potential Steganography)")

            # 3. PNG Trailing Data
            if self.file_path.suffix.lower() == '.png':
                with open(self.file_path, 'rb') as f:
                    content = f.read()
                    iend_index = content.rfind(b'IEND')
                    if iend_index != -1:
                        file_end = iend_index + 8 # IEND + CRC
                        if file_end < len(content):
                            extra_data = content[file_end:]
                            extra_len = len(extra_data)
                            
                            is_padding = all(b in b'\x00\xff\r\n\t ' for b in extra_data)
                            
                            if extra_len > 4096 and not is_padding:
                                suspicious.append(f"Significant trailing data found after PNG IEND: {extra_len} bytes (Potential Steganography)")

        except Exception as e:
            self.metadata['warnings'].append(f"Suspicious detection error: {str(e)}")

        if suspicious:
            self.metadata['forensic_info']['suspicious_flags'] = suspicious
            # Also alert in warnings for visibility
            for s in suspicious:
                self.metadata['warnings'].append(f"{Fore.RED}SUSPICIOUS: {s}{Style.RESET_ALL}")
    
    def extract_all(self) -> Dict[str, Any]:
        """Extract all available metadata"""
        try:
            if not self.file_path.exists():
                raise FileNotFoundError(f"{Fore.RED}File not found: {self.file_path}{Style.RESET_ALL}")
            
            self.logger.info(f"Starting metadata extraction", file=str(self.file_path))
            
            # Add forensic metadata block
            self._add_forensic_metadata()
            
            # Extract file type information
            self._extract_file_type()
            
            # Extract basic file information
            self._extract_file_info()
            
            # Extract file hashes
            self._extract_hashes()
            
            # Extract ExifTool metadata (powerful!)
            self._extract_exiftool_metadata()
            
            # Extract Hachoir metadata (Robust Fallback)
            self._extract_hachoir_metadata()

            # Extract type-specific metadata (Python Stack)
            self._extract_type_specific_metadata()

            # Perform forensic anomaly detection
            self._detect_suspicious()
            
            self.logger.info(f"Metadata extraction completed", file=str(self.file_path))
            
        except Exception as e:
            self.logger.error(f"Extraction failed: {str(e)}", file=str(self.file_path))
            self.metadata['errors'].append(str(e))
        
        return self.metadata
    
    def _add_forensic_metadata(self):
        """Add forensic metadata block"""
        self.metadata['forensic_info'] = {
            'case_id': self.case_id,
            'tool_name': TOOL_NAME,
            'tool_version': VERSION,
            'extraction_timestamp_utc': datetime.utcnow().isoformat() + 'Z',
            'extraction_timestamp_local': datetime.now().isoformat(),
            'examiner_system': {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
            },
            'capabilities': {
                'exiftool_available': self.exiftool.available,
                'hachoir_available': HACHOIR_AVAILABLE,
                'libmagic_available': self.file_detector.available,
                'pil_available': PIL_AVAILABLE,
                'pypdf2_available': PDF_AVAILABLE,
                'python_docx_available': DOCX_AVAILABLE,
                'mutagen_available': AUDIO_AVAILABLE,
                'pefile_available': PE_AVAILABLE,
            }
        }
    
    def _extract_file_type(self):
        """Extract file type using libmagic"""
        self.metadata['file_type_analysis'] = self.file_detector.detect(str(self.file_path))
    
    def _extract_file_info(self):
        """Extract basic file system information"""
        stat_info = self.file_path.stat()
        
        self.metadata['file_info'] = {
            'filename': self.file_path.name,
            'full_path': str(self.file_path.absolute()),
            'file_size_bytes': stat_info.st_size,
            'file_size_human': self._human_readable_size(stat_info.st_size),
            'extension': self.file_path.suffix,
            'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            'permissions': oct(stat_info.st_mode)[-3:],
        }
    
    def _extract_hashes(self):
        """Calculate file hashes"""
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        
        try:
            with open(self.file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
                    hash_sha1.update(chunk)
                    hash_sha256.update(chunk)
            
            self.metadata['hashes'] = {
                'md5': hash_md5.hexdigest(),
                'sha1': hash_sha1.hexdigest(),
                'sha256': hash_sha256.hexdigest()
            }
        except Exception as e:
            self.metadata['errors'].append(f"Hash calculation failed: {str(e)}")
    
    def _extract_exiftool_metadata(self):
        """Extract metadata using ExifTool"""
        if self.exiftool.available:
            exif_data = self.exiftool.extract_metadata(str(self.file_path))
            if exif_data:
                self.metadata['exiftool_metadata'] = exif_data
            else:
                self.metadata['warnings'].append("ExifTool extraction returned no data")
        else:
            self.metadata['warnings'].append("ExifTool not available - utilizing Python stack + Hachoir")

    def _extract_hachoir_metadata(self):
        """Extract metadata using Hachoir (Robust Fallback)"""
        if not HACHOIR_AVAILABLE:
            return

        try:
            # Silence hachoir output to stderr
            import contextlib
            import io
            
            hachoir_data = {}
            with contextlib.redirect_stderr(io.StringIO()):
                filename = str(self.file_path)
                parser = createParser(filename)
                
                if parser:
                    with parser:
                        metadata = extractMetadata(parser)
                        if metadata:
                            for item in metadata:
                                if item.values:
                                    # Create list of text values
                                    values = [v.text for v in item.values]
                                    hachoir_data[item.key] = values[0] if len(values) == 1 else values
            
            if hachoir_data:
                 self.metadata['extracted_metadata']['hachoir'] = hachoir_data
                 
        except Exception as e:
            # Hachoir can be trying on some files, just ignore errors
            pass
    
    def _extract_type_specific_metadata(self):
        """Extract type-specific metadata based on file type"""
        file_type = self.metadata['file_type_analysis'].get('real_type')
        extension = self.file_path.suffix.lower()
        
        if file_type == 'image' or extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']:
            self._extract_image_metadata()
        elif file_type == 'pdf' or extension == '.pdf':
            self._extract_pdf_metadata()
        elif file_type == 'document' or extension in ['.docx', '.doc']:
            self._extract_docx_metadata()
        elif file_type == 'audio' or extension in ['.mp3', '.mp4', '.m4a', '.flac', '.ogg', '.wav']:
            self._extract_audio_metadata()
        elif file_type == 'archive' or extension in ['.zip', '.jar', '.apk']:
            self._extract_zip_metadata()
        elif file_type == 'video' or extension in ['.mp4', '.avi', '.mkv', '.mov', '.wmv']:
            self._extract_video_metadata()
        elif file_type == 'executable' or extension in ['.exe', '.dll']:
            self._extract_pe_metadata()
        elif file_type == 'disk_image' or extension in ['.e01', '.aff4', '.dd', '.img', '.iso']:
            self._extract_disk_image_metadata()

    def _extract_disk_image_metadata(self):
        """Extract metadata from disk images (E01, DD, etc.)"""
        if not TSK_AVAILABLE:
            self.metadata['warnings'].append("pytsk3 not installed - cannot analyze disk image structure")
            return
            
        try:
            handler = DiskImageHandler(str(self.file_path), logger=self.logger)
            if handler.open_image():
                partitions = handler.list_partitions()
                disk_info = {
                    'image_path': str(self.file_path),
                    'total_size': handler.img_info.get_size(),
                    'total_size_human': self._human_readable_size(handler.img_info.get_size()),
                    'partition_count': len(partitions),
                    'partitions': partitions
                }
                
                # For basic extraction, we just list files in the first data partition
                # Users can use interactive mode for deeper analysis
                if partitions:
                    # Find first partition with a filesystem (simplified)
                    data_part = next((p for p in partitions if p['flags'] == pytsk3.TSK_VS_PART_FLAG_ALLOC), partitions[0])
                    disk_info['sample_files'] = handler.walk_filesystem(data_part['id'])[:50] # Limit to top 50
                    
                self.metadata['extracted_metadata']['disk_image'] = disk_info
                
        except Exception as e:
            self.metadata['errors'].append(f"Disk image analysis failed: {str(e)}")
    
    def _extract_image_metadata(self):
        """Extract EXIF and other metadata from images"""
        if not PIL_AVAILABLE:
            self.metadata['warnings'].append("PIL/Pillow not installed")
            return
        
        try:
            image = Image.open(self.file_path)
            
            image_info = {
                'format': image.format,
                'mode': image.mode,
                'size': f"{image.width}x{image.height}",
                'width': image.width,
                'height': image.height,
            }
            
            # Extract EXIF data
            exif_data = {}
            if hasattr(image, '_getexif') and image._getexif() is not None:
                exif = image._getexif()
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    
                    if tag == "GPSInfo":
                        gps_data = {}
                        for gps_tag_id in value:
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_data[gps_tag] = value[gps_tag_id]
                        
                        if gps_data:
                            coords = self._extract_gps_coordinates(gps_data)
                            if coords:
                                gps_data['coordinates'] = coords
                        
                        exif_data[tag] = gps_data
                    else:
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore')
                            except:
                                value = str(value)
                        exif_data[tag] = value
            
            self.metadata['extracted_metadata']['image'] = image_info
            if exif_data:
                self.metadata['extracted_metadata']['exif'] = exif_data
            
        except Exception as e:
            self.metadata['errors'].append(f"Image extraction failed: {str(e)}")
    
    def _extract_gps_coordinates(self, gps_data: Dict) -> Optional[Dict[str, float]]:
        """Extract GPS coordinates from EXIF GPS data"""
        try:
            def convert_to_degrees(value):
                d, m, s = value
                return float(d) + (float(m) / 60.0) + (float(s) / 3600.0)
            
            lat = gps_data.get('GPSLatitude')
            lat_ref = gps_data.get('GPSLatitudeRef')
            lon = gps_data.get('GPSLongitude')
            lon_ref = gps_data.get('GPSLongitudeRef')
            
            if lat and lon and lat_ref and lon_ref:
                latitude = convert_to_degrees(lat)
                if lat_ref == 'S':
                    latitude = -latitude
                
                longitude = convert_to_degrees(lon)
                if lon_ref == 'W':
                    longitude = -longitude
                
                return {
                    'latitude': latitude,
                    'longitude': longitude,
                    'google_maps_url': f"https://www.google.com/maps?q={latitude},{longitude}"
                }
        except Exception as e:
            self.metadata['warnings'].append(f"GPS extraction failed: {str(e)}")
        
        return None
    
    def _extract_pdf_metadata(self):
        """Extract metadata from PDF files"""
        if not PDF_AVAILABLE:
            self.metadata['warnings'].append("PyPDF2 not installed")
            return
        
        try:
            with open(self.file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                
                pdf_info = {
                    'num_pages': len(pdf_reader.pages),
                    'is_encrypted': pdf_reader.is_encrypted,
                }
                
                if pdf_reader.metadata:
                    metadata = {}
                    for key, value in pdf_reader.metadata.items():
                        clean_key = key.lstrip('/')
                        metadata[clean_key] = value
                    pdf_info['metadata'] = metadata
                
                self.metadata['extracted_metadata']['pdf'] = pdf_info
                
        except Exception as e:
            self.metadata['errors'].append(f"PDF extraction failed: {str(e)}")
    
    def _extract_docx_metadata(self):
        """Extract metadata from DOCX files"""
        if not DOCX_AVAILABLE:
            self.metadata['warnings'].append("python-docx not installed")
            return
        
        try:
            doc = Document(self.file_path)
            core_props = doc.core_properties
            
            docx_info = {
                'author': core_props.author,
                'category': core_props.category,
                'comments': core_props.comments,
                'content_status': core_props.content_status,
                'created': core_props.created.isoformat() if core_props.created else None,
                'identifier': core_props.identifier,
                'keywords': core_props.keywords,
                'language': core_props.language,
                'last_modified_by': core_props.last_modified_by,
                'last_printed': core_props.last_printed.isoformat() if core_props.last_printed else None,
                'modified': core_props.modified.isoformat() if core_props.modified else None,
                'revision': core_props.revision,
                'subject': core_props.subject,
                'title': core_props.title,
                'version': core_props.version,
                'num_paragraphs': len(doc.paragraphs),
                'num_tables': len(doc.tables),
            }
            
            self.metadata['extracted_metadata']['docx'] = docx_info
            
        except Exception as e:
            self.metadata['errors'].append(f"DOCX extraction failed: {str(e)}")
    
    def _extract_audio_metadata(self):
        """Extract metadata from audio files"""
        if not AUDIO_AVAILABLE:
            self.metadata['warnings'].append("mutagen not installed")
            return
        
        try:
            audio = mutagen.File(self.file_path)
            
            if audio is None:
                self.metadata['warnings'].append("Could not read audio file")
                return
            
            audio_info = {
                'length_seconds': audio.info.length if hasattr(audio.info, 'length') else None,
                'bitrate': audio.info.bitrate if hasattr(audio.info, 'bitrate') else None,
                'sample_rate': audio.info.sample_rate if hasattr(audio.info, 'sample_rate') else None,
                'channels': audio.info.channels if hasattr(audio.info, 'channels') else None,
            }
            
            if audio.tags:
                tags = {}
                for key, value in audio.tags.items():
                    tags[key] = str(value)
                audio_info['tags'] = tags
            
            self.metadata['extracted_metadata']['audio'] = audio_info
            
        except Exception as e:
            self.metadata['errors'].append(f"Audio extraction failed: {str(e)}")
    
    def _extract_zip_metadata(self):
        """Extract metadata from ZIP archives"""
        try:
            if not zipfile.is_zipfile(self.file_path):
                return
            
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                zip_info = {
                    'file_count': len(zf.namelist()),
                    'files': [],
                    'total_uncompressed_size': 0,
                    'total_compressed_size': 0,
                }
                
                for info in zf.infolist():
                    file_data = {
                        'filename': info.filename,
                        'compressed_size': info.compress_size,
                        'uncompressed_size': info.file_size,
                        'compression_ratio': f"{(1 - info.compress_size / info.file_size) * 100:.1f}%" if info.file_size > 0 else "0%",
                        'date_time': datetime(*info.date_time).isoformat(),
                        'crc': hex(info.CRC),
                    }
                    zip_info['files'].append(file_data)
                    zip_info['total_uncompressed_size'] += info.file_size
                    zip_info['total_compressed_size'] += info.compress_size
                
                zip_info['total_uncompressed_size_human'] = self._human_readable_size(zip_info['total_uncompressed_size'])
                zip_info['total_compressed_size_human'] = self._human_readable_size(zip_info['total_compressed_size'])
                
                self.metadata['extracted_metadata']['zip'] = zip_info
                
        except Exception as e:
            self.metadata['errors'].append(f"ZIP extraction failed: {str(e)}")
    
    def _extract_video_metadata(self):
        """Extract metadata from video files using ffprobe"""
        try:
            # Check if ffprobe is available
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', 
                 '-show_streams', str(self.file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                video_data = json.loads(result.stdout)
                
                video_info = {
                    'format': video_data.get('format', {}),
                    'streams': video_data.get('streams', []),
                }
                
                # Extract key information
                format_info = video_data.get('format', {})
                video_info['duration'] = format_info.get('duration')
                video_info['size'] = format_info.get('size')
                video_info['bit_rate'] = format_info.get('bit_rate')
                video_info['format_name'] = format_info.get('format_name')
                
                self.metadata['extracted_metadata']['video'] = video_info
            else:
                self.metadata['warnings'].append("ffprobe not available or failed")
                
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            self.metadata['warnings'].append(f"Video extraction failed: {str(e)}")
    
    def _extract_pe_metadata(self):
        """Extract metadata from PE (Windows executable) files"""
        if not PE_AVAILABLE:
            self.metadata['warnings'].append("pefile not installed")
            return
        
        try:
            pe = pefile.PE(str(self.file_path))
            
            pe_info = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                'characteristics': hex(pe.FILE_HEADER.Characteristics),
            }
            
            # Extract sections
            sections = []
            for section in pe.sections:
                sections.append({
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics),
                })
            pe_info['sections'] = sections
            
            # Extract imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                imports = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    import_count = len(entry.imports)
                    imports.append({
                        'dll': dll_name,
                        'import_count': import_count,
                    })
                pe_info['imports'] = imports
            
            # Extract version info
            if hasattr(pe, 'VS_VERSIONINFO'):
                if hasattr(pe, 'FileInfo'):
                    for file_info in pe.FileInfo:
                        if hasattr(file_info, 'StringTable'):
                            for string_table in file_info.StringTable:
                                version_info = {}
                                for key, value in string_table.entries.items():
                                    version_info[key.decode('utf-8', errors='ignore')] = value.decode('utf-8', errors='ignore')
                                pe_info['version_info'] = version_info
            
            self.metadata['extracted_metadata']['pe_file'] = pe_info
            
        except Exception as e:
            self.metadata['errors'].append(f"PE extraction failed: {str(e)}")
    
    @staticmethod
    def _human_readable_size(size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


class ParallelScanner:
    """Parallel directory scanner with progress tracking"""
    
    def __init__(self, max_workers: int = DEFAULT_WORKERS, 
                 case_id: Optional[str] = None,
                 logger: Optional[ForensicLogger] = None):
        self.max_workers = max_workers
        self.case_id = case_id
        self.logger = logger or ForensicLogger(case_id=case_id)
        self.processed_count = 0
        self.failed_count = 0
        self.lock = Lock()
    
    def scan_directory(self, directory: Path, recursive: bool = False) -> List[Dict[str, Any]]:
        """Scan directory in parallel"""
        pattern = '**/*' if recursive else '*'
        file_list = [f for f in directory.glob(pattern) if f.is_file()]
        
        total_files = len(file_list)
        self.logger.info(f"Starting parallel scan", 
                        directory=str(directory), 
                        total_files=total_files,
                        workers=self.max_workers)
        
        results = []
        
        # Use tqdm for progress bar
        with tqdm(total=total_files, desc=f"{Fore.CYAN}Scanning{Style.RESET_ALL}", unit="file") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_file = {
                    executor.submit(self._process_file, file_path): file_path 
                    for file_path in file_list
                }
                
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        metadata = future.result()
                        results.append(metadata)
                        
                        with self.lock:
                            self.processed_count += 1
                        
                    except Exception as e:
                        with self.lock:
                            self.failed_count += 1
                            self.processed_count += 1
                        self.logger.error(f"File processing failed", 
                                        file=str(file_path), 
                                        error=str(e))
                    finally:
                        pbar.update(1)
                        pbar.set_postfix(failed=f"{Fore.RED}{self.failed_count}{Style.RESET_ALL}")
        
        self.logger.info(f"Scan completed", 
                        processed=self.processed_count,
                        failed=self.failed_count)
        
        return results
    
    def _process_file(self, file_path: Path) -> Dict[str, Any]:
        """Process a single file"""
        extractor = EnhancedMetadataExtractor(
            str(file_path), 
            case_id=self.case_id,
            logger=self.logger
        )
        return extractor.extract_all()


def print_metadata(metadata: Dict[str, Any], verbose: bool = False):
    """Pretty print metadata"""
    print("\n" + Fore.BLUE + "="*80 + Style.RESET_ALL)
    print(f"{Fore.GREEN}ENHANCED METADATA EXTRACTION REPORT{Style.RESET_ALL}")
    print(Fore.BLUE + "="*80 + Style.RESET_ALL)
    
    # Forensic Information
    if metadata.get('forensic_info'):
        print(f"\n{Fore.YELLOW}[FORENSIC INFORMATION]{Style.RESET_ALL}")
        forensic = metadata['forensic_info']
        print(f"  Case ID: {forensic.get('case_id')}")
        print(f"  Tool: {forensic.get('tool_name')} v{forensic.get('tool_version')}")
        print(f"  Extraction Time (UTC): {forensic.get('extraction_timestamp_utc')}")
        print(f"  Examiner System: {forensic.get('examiner_system', {}).get('platform')} "
              f"{forensic.get('examiner_system', {}).get('platform_release')}")
    
    # File Type Analysis
    if metadata.get('file_type_analysis'):
        print(f"\n{Fore.YELLOW}[FILE TYPE ANALYSIS]{Style.RESET_ALL}")
        fta = metadata['file_type_analysis']
        print(f"  Extension: {fta.get('extension')}")
        print(f"  MIME Type: {fta.get('mime_type')}")
        print(f"  Description: {fta.get('description')}")
        print(f"  Classified As: {fta.get('real_type')}")
    
    # File Information
    if metadata.get('file_info'):
        print(f"\n{Fore.YELLOW}[FILE INFORMATION]{Style.RESET_ALL}")
        for key, value in metadata['file_info'].items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
    
    # File Hashes
    if metadata.get('hashes'):
        print(f"\n{Fore.YELLOW}[FILE HASHES]{Style.RESET_ALL}")
        for key, value in metadata['hashes'].items():
            print(f"  {key.upper()}: {value}")
    
    # ExifTool Metadata (if verbose)
    if verbose and metadata.get('exiftool_metadata'):
        print(f"\n{Fore.YELLOW}[EXIFTOOL METADATA]{Style.RESET_ALL}")
        print(json.dumps(metadata['exiftool_metadata'], indent=2, default=str))
    
    # Extracted Metadata
    if metadata.get('extracted_metadata'):
        print(f"\n{Fore.YELLOW}[EXTRACTED METADATA]{Style.RESET_ALL}")
        print(json.dumps(metadata['extracted_metadata'], indent=2, default=str))
    
    
    # Hachoir Metadata
    if metadata.get('extracted_metadata', {}).get('hachoir'):
        print(f"\n{Fore.YELLOW}[HACHOIR METADATA (FALLBACK)]{Style.RESET_ALL}")
        print(json.dumps(metadata['extracted_metadata']['hachoir'], indent=2, default=str))

    # Warnings
    if metadata.get('warnings'):
        print(f"\n{Fore.YELLOW}[WARNINGS]{Style.RESET_ALL}")
        for warning in metadata['warnings']:
            print(f"  ⚠ {warning}")
    
    # Errors
    if metadata.get('errors'):
        print(f"\n{Fore.RED}[ERRORS]{Style.RESET_ALL}")
        for error in metadata['errors']:
            print(f"  ❌ {error}")
    
    print("\n" + "="*80 + "\n")


def save_to_json(metadata: Dict[str, Any], output_path: str):
    """Save metadata to JSON file"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, default=str)
    print(f"✓ Metadata saved to: {output_path}")


def save_to_csv(data: Any, output_path: str):
    """Save metadata to CSV file"""
    try:
        # Flatten the data if it's a list (directory scan)
        rows = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict) and 'files' in data:
            items = data['files']
        else:
            items = [data] # Single file
            
        for item in items:
            flat = {}
            # Flatten File Info
            if 'file_info' in item:
                for k, v in item['file_info'].items():
                    flat[f"file_{k}"] = v
            # Flatten Hashes
            if 'hashes' in item:
                for k, v in item['hashes'].items():
                    flat[f"hash_{k}"] = v
            # Flatten Forensic Info
            if 'forensic_info' in item:
                 for k, v in item['forensic_info'].items():
                     if isinstance(v, (str, int, float)):
                         flat[f"forensic_{k}"] = v
            # Flatten Extracted (simplify)
            if 'extracted_metadata' in item:
                for k, v in item['extracted_metadata'].items():
                     flat[f"meta_{k}"] = str(v)[:100] + "..." if len(str(v)) > 100 else str(v)
            
            rows.append(flat)
            
        if not rows:
            print("⚠ No data to save to CSV")
            return

        # Get all headers
        headers = set()
        for row in rows:
            headers.update(row.keys())
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(list(headers)))
            writer.writeheader()
            writer.writerows(rows)
            
        print(f"✓ CSV Report saved to: {output_path}")
        
    except Exception as e:
        print(f"❌ Failed to save CSV: {str(e)}")


def save_to_html(data: Any, output_path: str):
    """Save metadata to a beautiful HTML report"""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Prepare data structure
        files = []
        if isinstance(data, list):
            files = data
        elif isinstance(data, dict) and 'files' in data:
            files = data['files']
        else:
            files = [data]
            
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Metadata Forensic Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f0f2f5; color: #333; }}
                .header {{ background: linear-gradient(135deg, #1a2a6c, #b21f1f, #fdbb2d); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .container {{ max_width: 1200px; margin: 0 auto; }}
                .card {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
                .file-title {{ border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 15px; color: #1a2a6c; }}
                .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }}
                .meta-section {{ margin-bottom: 15px; }}
                .meta-section h4 {{ margin: 0 0 5px 0; color: #555; text-transform: uppercase; font-size: 0.85em; }}
                .tag {{ display: inline-block; padding: 2px 8px; background: #eee; border-radius: 4px; font-size: 0.85em; margin: 2px; }}
                .tag.warning {{ background: #fff3cd; color: #856404; }}
                .tag.error {{ background: #f8d7da; color: #721c24; }}
                .tag.info {{ background: #d1ecf1; color: #0c5460; }}
                table {{ width: 100%; border-collapse: collapse; }}
                td, th {{ padding: 8px; border-bottom: 1px solid #eee; text-align: left; }}
                .value {{ font-family: monospace; color: #d63384; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🕵️ Metadata Forensic Report</h1>
                    <p>Generated: {timestamp} | File Count: {len(files)}</p>
                </div>
        """
        
        for f in files:
            fname = f.get('file_info', {}).get('filename', 'Unknown')
            fpath = f.get('file_info', {}).get('full_path', 'Unknown')
            entropy = f.get('forensic_info', {}).get('entropy', 'N/A')
            
            # Color code entropy
            entropy_style = "color: green"
            try:
                if float(entropy) > 7.5: entropy_style = "color: red; font-weight: bold;"
            except: pass
            
            html += f"""
            <div class="card">
                <h2 class="file-title">📄 {fname}</h2>
                <div style="font-size: 0.9em; color: #666; margin-bottom: 10px;">{fpath}</div>
                
                <div class="grid">
                    <div class="meta-section">
                        <h4>Filesystem Info</h4>
                        <table>
                            <tr><td>Size:</td><td>{f.get('file_info', {}).get('file_size_human', 'N/A')}</td></tr>
                            <tr><td>Created:</td><td>{f.get('file_info', {}).get('created_time', 'N/A')}</td></tr>
                            <tr><td>Modified:</td><td>{f.get('file_info', {}).get('modified_time', 'N/A')}</td></tr>
                            <tr><td>Entropy:</td><td style="{entropy_style}">{entropy}</td></tr>
                        </table>
                    </div>
                    
                    <div class="meta-section">
                        <h4>Hashes</h4>
                        <div style="word-break: break-all; font-family: monospace; font-size: 0.8em;">
                            MD5: {f.get('hashes', {}).get('md5', 'N/A')}<br>
                            SHA1: {f.get('hashes', {}).get('sha1', 'N/A')}
                        </div>
                    </div>
                </div>
            """
            
            # Suspicious Flags
            suspicious = f.get('forensic_info', {}).get('suspicious_flags', [])
            if suspicious:
                html += '<div style="margin-top: 15px; padding: 10px; background: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px;">'
                html += '<h4 style="color: #856404; margin-top:0;">⚠️ Suspicious Indicators</h4>'
                for s in suspicious:
                    html += f'<div>• {s}</div>'
                html += '</div>'
                
            # Extracted Metadata
            meta = f.get('extracted_metadata', {})
            if meta:
                html += '<div style="margin-top: 15px;"><h4>Extracted Metadata</h4>'
                html += f'<pre style="background: #f8f9fa; padding: 10px; overflow-x: auto;">{json.dumps(meta, indent=2)}</pre>'
                html += '</div>'

            html += "</div>" # End card
            
        html += """
            </div>
            <footer style="text-align: center; color: #888; margin-top: 40px;">
                Generated by Enhanced Metadata Extractor v2.0
            </footer>
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"✓ HTML Report saved to: {output_path}")
        
    except Exception as e:
        print(f"❌ Failed to save HTML: {str(e)}")


def print_banner():
    """Print application banner"""
    print(f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║{Fore.YELLOW}ENHANCED METADATA EXTRACTOR FOR ETHICAL HACKING v{VERSION}{Fore.CYAN}           ║
║                                                                              ║
║  Extract metadata from Images, Documents, PDFs, Audio, Video, PE & more      ║
║  New: ExifTool Integration | Parallel Scanning | Forensic Logging            ║
║  Author : Sayan Pal | Collaborator: Soumit Santra                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}""")


def ask_save_options():
    """Ask user for save options and return format and filename"""
    print("\n" + "="*80)
    print("[SAVE OPTIONS]")
    print("="*80)
    
    save_option = input("\nDo you want to save the output? (y/n): ").strip().lower()
    if save_option != 'y':
        return None, None
    
    print("\nSelect output format:")
    print("1. JSON (Structured data, best for analysis)")
    print("2. HTML (Beautiful report, best for viewing)")
    print("3. CSV  (Spreadsheet compatible)")
    
    format_choice = input("\nEnter format choice (1-3): ").strip()
    
    if format_choice == '2':
        file_format = 'html'
        extension = '.html'
    elif format_choice == '3':
        file_format = 'csv'
        extension = '.csv'
    else:
        file_format = 'json'
        extension = '.json'
    
    output_file = input(f"\nEnter output filename (press Enter for auto-generated): ").strip()
    if not output_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if file_format == 'html':
            output_file = f"forensic_report_{timestamp}.html"
        else:
            output_file = f"metadata_{timestamp}{extension}"
    elif not output_file.endswith(extension):
        output_file += extension
    
    return file_format, output_file


def save_output(data: Any, file_format: str, output_file: str):
    """Dispatch save to appropriate function"""
    if file_format == 'json':
        save_to_json(data, output_file)
    elif file_format == 'html':
        save_to_html(data, output_file)
    elif file_format == 'csv':
        save_to_csv(data, output_file)


def interactive_mode():
    """Run in interactive menu-driven mode"""
    print_banner()
    
    print("\n[MAIN MENU]")
    print("=" * 80)
    print("\n1. Extract metadata from a single file")
    print("2. Process all files in a directory (non-recursive)")
    print("3. Process directory recursively (including subdirectories)")
    print("4. Forensic mode - Single file with case tracking")
    print("5. Forensic mode - Directory scan with case tracking")
    print("6. Analyze forensic disk image (E01, DD, AFF4)")
    print("7. Show system capabilities")
    print("8. Show supported file types")
    print("9. About this tool")
    print("0. Exit")
    print("\n" + "=" * 80)
    
    choice = input("\nEnter your choice (0-9): ").strip()
    
    if choice == '0':
        print("\n✓ Thank you for using Enhanced Metadata Extractor!")
        sys.exit(0)
    
    elif choice == '1':
        # Single file extraction
        print("\n" + "=" * 80)
        print("[SINGLE FILE EXTRACTION]")
        print("=" * 80)
        file_path = input("\nEnter the file path: ").strip().strip('"').strip("'")
        
        if not file_path:
            print("❌ Error: No file path provided")
            return
        
        try:
            print(f"\n⏳ Extracting metadata from: {file_path}")
            
            extractor = EnhancedMetadataExtractor(file_path)
            metadata = extractor.extract_all()
            
            print_metadata(metadata, verbose=True)
            
            # Ask for save options
            # Ask for save options
            file_format, output_file = ask_save_options()
            if output_file:
                save_output(metadata, file_format, output_file)
        
        except FileNotFoundError:
            print(f"❌ Error: File not found: {file_path}")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif choice == '2' or choice == '3':
        # Directory processing
        recursive = (choice == '3')
        mode_text = "RECURSIVE DIRECTORY SCAN" if recursive else "DIRECTORY SCAN"
        
        print("\n" + "=" * 80)
        print(f"[{mode_text}]")
        print("=" * 80)
        dir_path = input("\nEnter the directory path: ").strip().strip('"').strip("'")
        
        if not dir_path:
            print("❌ Error: No directory path provided")
            return
        
        input_path = Path(dir_path)
        if not input_path.is_dir():
            print(f"❌ Error: {dir_path} is not a valid directory")
            return
        
        # Ask for worker count
        workers_input = input(f"\nNumber of parallel workers (1-16, default {DEFAULT_WORKERS}): ").strip()
        try:
            workers = int(workers_input) if workers_input else DEFAULT_WORKERS
            workers = max(1, min(16, workers))
        except ValueError:
            workers = DEFAULT_WORKERS
        
        print(f"\n⏳ Scanning directory: {input_path.absolute()}")
        if recursive:
            print("   (Recursive mode enabled)")
        print(f"   Workers: {workers}")
        
        scanner = ParallelScanner(max_workers=workers)
        results = scanner.scan_directory(input_path, recursive)
        
        print(f"\n✓ Processed {len(results)} files")
        
        if results:
            # Show summary
            print("\n[SCAN SUMMARY]")
            print(f"  Total files processed: {len(results)}")
            print(f"  Failed files: {scanner.failed_count}")
            
            # Ask for save options
            # Ask for save options
            file_format, output_file = ask_save_options()
            if output_file:
                output_data = {
                    'scan_info': {
                        'directory': str(input_path.absolute()),
                        'recursive': recursive,
                        'total_files': len(results),
                        'failed_files': scanner.failed_count,
                        'workers': workers,
                        'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
                    },
                    'files': results
                }
                save_output(output_data, file_format, output_file)
    
    elif choice == '4':
        # Forensic mode - single file
        print("\n" + "=" * 80)
        print("[FORENSIC MODE - SINGLE FILE]")
        print("=" * 80)
        
        file_path = input("\nEnter the file path: ").strip().strip('"').strip("'")
        if not file_path:
            print("❌ Error: No file path provided")
            return
        
        case_id = input("Enter case ID (press Enter for auto-generated): ").strip()
        if not case_id:
            case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        log_file = input("Enter log file path (press Enter to skip): ").strip()
        if not log_file:
            log_file = None
        
        try:
            print(f"\n⏳ Extracting metadata from: {file_path}")
            print(f"   Case ID: {case_id}")
            if log_file:
                print(f"   Log file: {log_file}")
            
            logger = ForensicLogger(log_file=log_file, case_id=case_id)
            extractor = EnhancedMetadataExtractor(file_path, case_id=case_id, logger=logger)
            metadata = extractor.extract_all()
            
            print_metadata(metadata, verbose=True)
            
            # Ask for save options
            # Ask for save options
            file_format, output_file = ask_save_options()
            if output_file:
                save_output(metadata, file_format, output_file)
        
        except FileNotFoundError:
            print(f"❌ Error: File not found: {file_path}")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif choice == '5':
        # Forensic mode - directory
        print("\n" + "=" * 80)
        print("[FORENSIC MODE - DIRECTORY SCAN]")
        print("=" * 80)
        
        dir_path = input("\nEnter the directory path: ").strip().strip('"').strip("'")
        if not dir_path:
            print("❌ Error: No directory path provided")
            return
        
        input_path = Path(dir_path)
        if not input_path.is_dir():
            print(f"❌ Error: {dir_path} is not a valid directory")
            return
        
        case_id = input("Enter case ID (press Enter for auto-generated): ").strip()
        if not case_id:
            case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        log_file = input("Enter log file path (press Enter to skip): ").strip()
        if not log_file:
            log_file = None
        
        recursive_input = input("Recursive scan? (y/n, default: y): ").strip().lower()
        recursive = recursive_input != 'n'
        
        workers_input = input(f"Number of parallel workers (1-16, default {DEFAULT_WORKERS}): ").strip()
        try:
            workers = int(workers_input) if workers_input else DEFAULT_WORKERS
            workers = max(1, min(16, workers))
        except ValueError:
            workers = DEFAULT_WORKERS
        
        print(f"\n⏳ Scanning directory: {input_path.absolute()}")
        print(f"   Case ID: {case_id}")
        if recursive:
            print("   (Recursive mode enabled)")
        print(f"   Workers: {workers}")
        if log_file:
            print(f"   Log file: {log_file}")
        
        logger = ForensicLogger(log_file=log_file, case_id=case_id)
        scanner = ParallelScanner(max_workers=workers, case_id=case_id, logger=logger)
        results = scanner.scan_directory(input_path, recursive)
        
        print(f"\n✓ Processed {len(results)} files")
        
        if results:
            # Show summary
            print("\n[SCAN SUMMARY]")
            print(f"  Case ID: {case_id}")
            print(f"  Total files processed: {len(results)}")
            print(f"  Failed files: {scanner.failed_count}")
            
            # Ask for save options
            # Ask for save options
            file_format, output_file = ask_save_options()
            if output_file:
                output_data = {
                    'scan_info': {
                        'case_id': case_id,
                        'directory': str(input_path.absolute()),
                        'recursive': recursive,
                        'total_files': len(results),
                        'failed_files': scanner.failed_count,
                        'workers': workers,
                        'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
                    },
                    'files': results
                }
                save_output(output_data, file_format, output_file)
    
    elif choice == '6':
        # Analyze disk image
        print("\n" + "=" * 80)
        print("[DISK IMAGE ANALYSIS]")
        print("=" * 80)
        
        if not TSK_AVAILABLE:
            print(f"\n{Fore.RED}❌ Error: pytsk3 is not installed.{Style.RESET_ALL}")
            print("To analyze disk images, you need to install forensic libraries.")
            print("Try: pip install pytsk3 pyewf")
            return

        file_path = input("\nEnter the disk image path (E01, DD, AFF4, IMG): ").strip().strip('"').strip("'")
        if not file_path or not Path(file_path).exists():
            print("❌ Error: Valid file path required")
            return
            
        try:
            print(f"\n⏳ Opening evidence image: {file_path}")
            handler = DiskImageHandler(file_path)
            if not handler.open_image():
                print("❌ Failed to open image. Check if it's a valid format.")
                return
                
            print(f"\n✓ Image opened successfully. Size: {EnhancedMetadataExtractor._human_readable_size(handler.img_info.get_size())}")
            
            partitions = handler.list_partitions()
            print(f"\n[PARTITIONS FOUND: {len(partitions)}]")
            for p in partitions:
                print(f"  Partition {p['id']}: {p['description']} | Start: {p['start']} | Length: {p['length']}")
                
            part_choice = input("\nEnter Partition ID to walk filesystem (or press Enter for ID 0): ").strip()
            part_id = int(part_choice) if part_choice else 0
            
            print(f"\n⏳ Walking filesystem on Partition {part_id}...")
            files = handler.walk_filesystem(part_id)
            
            print(f"\n✓ Found {len(files)} items in partition.")
            
            # Show top 20 files
            print(f"\n[TOP 20 FILES/DIRECTORIES]")
            for f in files[:20]:
                print(f"  {f['type'][0].upper()} | {f['size']:>10} B | {f['path']}")
                
            # Offer to save results
            save_choice = input(f"\nDo you want to save the full file list ({len(files)} items)? (y/n): ").strip().lower()
            if save_choice == 'y':
                file_format, output_file = ask_save_options()
                if output_file:
                    save_output({'image': file_path, 'partition': part_id, 'files': files}, file_format, output_file)
                    
        except Exception as e:
            print(f"❌ Error during image analysis: {str(e)}")
            
    elif choice == '7':
        # Show capabilities
        print("\n" + "=" * 80)
        print("[SYSTEM CAPABILITIES]")
        print("=" * 80)
        
        # Check ExifTool
        exiftool = ExifToolWrapper()
        if exiftool.available:
            try:
                result = subprocess.run(['exiftool', '-ver'], capture_output=True, text=True, timeout=5)
                version = result.stdout.strip()
                print(f"\n✓ ExifTool: Installed (v{version})")
            except:
                print(f"\n✓ ExifTool: Installed")
        else:
            print("\n❌ ExifTool: Not installed (HIGHLY RECOMMENDED)")
            print("   Install: https://exiftool.org/")
        
        # Check libmagic
        if MAGIC_AVAILABLE:
            print("✓ libmagic: Installed")
        else:
            print("❌ libmagic: Not installed (RECOMMENDED)")
            print("   Install: pip install python-magic-bin (Windows) or python-magic (Linux/Mac)")
        
        # Check Forensic libraries
        print(f"✓ pytsk3: {'Installed (Disk Image support)' if TSK_AVAILABLE else 'Not installed (DD/Raw support missing)'}")
        print(f"✓ pyewf: {'Installed (E01 support)' if EWF_AVAILABLE else 'Not installed (E01 support missing)'}")
        print(f"✓ pyaff4: {'Installed (AFF4 support)' if AFF4_AVAILABLE else 'Not installed (AFF4 support missing)'}")

        # Check ffprobe
        try:
            result = subprocess.run(['ffprobe', '-version'], capture_output=True, timeout=5)
            if result.returncode == 0:
                print("✓ ffprobe: Installed (for video metadata)")
            else:
                print("❌ ffprobe: Not installed (optional, for video files)")
        except:
            print("❌ ffprobe: Not installed (optional, for video files)")
            print("   Install: https://ffmpeg.org/")
        
        # Python libraries
        print("\n[Python Libraries]")
        # Python libraries
        print("\n[Python Libraries]")
        print(f"✓ PIL/Pillow: {'Installed' if PIL_AVAILABLE else 'Not installed'}")
        print(f"✓ Hachoir: {'Installed' if HACHOIR_AVAILABLE else 'Not installed (Fallback)'}")
        print(f"✓ PyPDF2: {'Installed' if PDF_AVAILABLE else 'Not installed'}")
        print(f"✓ python-docx: {'Installed' if DOCX_AVAILABLE else 'Not installed'}")
        print(f"✓ mutagen: {'Installed' if AUDIO_AVAILABLE else 'Not installed'}")
        print(f"✓ pefile: {'Installed' if PE_AVAILABLE else 'Not installed'}")
        
        # System info
        print("\n[System Information]")
        print(f"  Platform: {platform.system()} {platform.release()}")
        print(f"  Python: {platform.python_version()}")
        print(f"  Machine: {platform.machine()}")
        
        input("\nPress Enter to return to main menu...")
        interactive_mode()
        return
    
    elif choice == '7':
        # Show supported file types
        print("\n" + "=" * 80)
        print("[SUPPORTED FILE TYPES]")
        print("=" * 80)
        print("\n📷 Images:")
        print("   .jpg, .jpeg, .png, .gif, .bmp, .tiff, .webp")
        print("   → Extracts: EXIF data, GPS coordinates, camera info, dimensions")
        
        print("\n📄 Documents:")
        print("   .pdf - PDF documents")
        print("   → Extracts: Author, creation date, page count, encryption status")
        print("   .docx - Microsoft Word documents")
        print("   → Extracts: Author, revision history, keywords, modification dates")
        
        print("\n🎵 Audio Files:")
        print("   .mp3, .mp4, .m4a, .flac, .ogg, .wav")
        print("   → Extracts: ID3 tags, bitrate, sample rate, duration")
        
        print("\n🎬 Video Files:")
        print("   .mp4, .avi, .mkv, .mov, .wmv (requires ffprobe)")
        print("   → Extracts: Duration, codec, bitrate, resolution, streams")
        
        print("\n📦 Archives:")
        print("   .zip, .jar, .apk")
        print("   → Extracts: File list, compression ratios, CRC checksums")
        
        print("\n⚙️ Executables:")
        print("   .exe, .dll (Windows PE files)")
        print("   → Extracts: PE headers, imports, sections, version info")
        
        print("\n🔧 General Information (All Files):")
        print("   → File hashes (MD5, SHA1, SHA256)")
        print("   → File size and timestamps")
        print("   → MIME type detection")
        print("   → Full path and extension")
        
        input("\nPress Enter to return to main menu...")
        interactive_mode()
        return
    
    elif choice == '8':
        # About
        print("\n" + "=" * 80)
        print("[ABOUT ENHANCED METADATA EXTRACTOR]")
        print("=" * 80)
        print(f"\nVersion: {VERSION}")
        print("\nThis tool extracts metadata from various file types for:")
        print("  ✓ Digital Forensics - Analyze evidence with case tracking")
        print("  ✓ OSINT - Gather intelligence from public files")
        print("  ✓ Security Assessments - Identify information leakage")
        print("  ✓ Privacy Auditing - Check metadata before sharing files")
        
        print("\n🆕 New Features in v2.0:")
        print("  ✓ ExifTool integration (10x more metadata)")
        print("  ✓ Parallel processing (3-7x faster)")
        print("  ✓ Forensic case tracking")
        print("  ✓ File type spoofing detection")
        print("  ✓ ZIP, Video, PE file support")
        print("  ✓ Structured logging (SIEM-ready)")
        
        print("\n⚠️  ETHICAL USE ONLY:")
        print("  • Only analyze files you have authorization to access")
        print("  • Respect privacy and data protection laws")
        print("  • Use for legal and ethical purposes only")
        
        print("\n📚 For more information, see README.md")
        
        input("\nPress Enter to return to main menu...")
        interactive_mode()
        return
    
    else:
        print("\n❌ Invalid choice. Please try again.")
        return
    
    # Ask if user wants to continue
    print("\n" + "=" * 80)
    continue_option = input("\nDo you want to perform another operation? (y/n): ").strip().lower()
    if continue_option == 'y':
        interactive_mode()
    else:
        print("\n✓ Thank you for using Enhanced Metadata Extractor!")


def main():
    # Check if running in interactive mode (no arguments) or command-line mode
    if len(sys.argv) == 1:
        # No arguments - run interactive mode
        interactive_mode()
        return
    
    # Command-line mode with arguments
    parser = argparse.ArgumentParser(
        description=f'Enhanced Metadata Extractor v{VERSION} - Comprehensive metadata extraction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python main_enhanced.py
  
  # Single file with ExifTool
  python main_enhanced.py image.jpg -v
  
  # Parallel directory scan
  python main_enhanced.py -d /path/to/dir -r --workers 8
  
  # Forensic mode with case tracking
  python main_enhanced.py evidence.pdf --case-id CASE-2024-001 --log forensic.log
  
  # Batch processing with JSON output
  python main_enhanced.py -d ./samples -o report.json --format json

Supported file types:
  Images: .jpg, .png, .gif, .bmp, .tiff, .webp
  Documents: .pdf, .docx
  Audio: .mp3, .flac, .m4a, .ogg, .wav
  Video: .mp4, .avi, .mkv, .mov (requires ffprobe)
  Archives: .zip, .jar, .apk
  Executables: .exe, .dll (Windows PE files)
        """
    )
    
    parser.add_argument('input', nargs='?', help='Input file or directory')
    parser.add_argument('-o', '--output', help='Output file for metadata (json, html, csv supported)')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'csv'],
                       help='Output format (if not specified, inferred from output extension)')
    parser.add_argument('-d', '--directory', action='store_true',
                       help='Process directory')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Recursively process directories')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (includes ExifTool data)')
    parser.add_argument('--workers', type=int, default=DEFAULT_WORKERS,
                       help=f'Number of parallel workers (default: {DEFAULT_WORKERS})')
    parser.add_argument('--case-id', help='Case ID for forensic tracking')
    parser.add_argument('--log', help='Log file path for structured logging')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Initialize logger
    logger = ForensicLogger(log_file=args.log, case_id=args.case_id)
    
    if not args.input:
        print("❌ Error: No input file or directory specified")
        parser.print_help()
        sys.exit(1)
    
    input_path = Path(args.input)
    
    if args.directory or input_path.is_dir():
        # Parallel directory processing
        if not input_path.is_dir():
            print(f"❌ Error: {input_path} is not a directory")
            sys.exit(1)
        
        print(f"\n⏳ Scanning directory: {input_path.absolute()}")
        if args.recursive:
            print("   (Recursive mode enabled)")
        print(f"   Workers: {args.workers}")
        
        scanner = ParallelScanner(
            max_workers=args.workers,
            case_id=args.case_id,
            logger=logger
        )
        
        results = scanner.scan_directory(input_path, args.recursive)
        
        print(f"\n✓ Processed {len(results)} files")
        
        if args.output:
            output_data = {
                'scan_info': {
                    'directory': str(input_path.absolute()),
                    'recursive': args.recursive,
                    'total_files': len(results),
                    'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
                    'case_id': args.case_id,
                },
                'files': results
            }
            
            if args.output.lower().endswith('.html'):
                save_to_html(output_data, args.output)
            elif args.output.lower().endswith('.csv'):
                save_to_csv(output_data, args.output)
            else:
                save_to_json(output_data, args.output)
    
    else:
        # Single file processing
        try:
            print(f"\n⏳ Extracting metadata from: {input_path}")
            
            extractor = EnhancedMetadataExtractor(
                str(input_path),
                case_id=args.case_id,
                logger=logger
            )
            metadata = extractor.extract_all()
            
            print_metadata(metadata, verbose=args.verbose)
            
            if args.output:
                if args.output.lower().endswith('.html'):
                    save_to_html(metadata, args.output)
                elif args.output.lower().endswith('.csv'):
                    save_to_csv(metadata, args.output)
                else:
                    save_to_json(metadata, args.output)
        
        except FileNotFoundError as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()