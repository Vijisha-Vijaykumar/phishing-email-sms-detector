"""
PhishGuard AI — Attachment Security Analyzer Service

Performs static analysis on user-submitted attachments within a quarantined temporary enclave.
CRITICAL SAFETY RULES:
- Never execute uploaded files, scripts, or binaries.
- Never execute macros or active content.
- Never pass user-controlled strings into shell commands.
- Never expose cybersecurity tool names (e.g. oletools, pefile, YARA, etc.) to the user UI.
- All temporary files are safely quarantined and removed immediately after analysis.
"""

import os
import re
import hashlib
import zipfile
import tempfile
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from app.services.url_analyzer import analyze_url_extended

_MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
_MAX_ZIP_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100 MB max uncompressed
_MAX_ZIP_RATIO = 100.0  # Max compression ratio (zip bomb defense)
_MAX_ARCHIVE_DEPTH = 3

QUARANTINE_DIR = Path(__file__).resolve().parent.parent.parent / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Dangerous extension list inside archives
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".cpl", ".pif", ".iso", ".img", ".vhd", ".dll",
    ".sys", ".msi", ".msp", ".jar", ".lnk", ".reg", ".bas"
}

# Suspicious PE API functions
SUSPICIOUS_PE_APIS = {
    "Process Injection": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "QueueUserAPC", "SetThreadContext"],
    "Memory Manipulation": ["VirtualAlloc", "VirtualProtect", "HeapCreate"],
    "Network / Downloader": ["URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW", "HttpOpenRequestA", "HttpOpenRequestW"],
    "Spyware / Keystrokes": ["GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW"],
    "Evasion / Anti-Debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA"],
    "Execution / Spawning": ["ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW", "WinExec"]
}


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def detect_real_file_type(header: bytes) -> str:
    """
    Identifies real file type using magic byte signatures.
    Does not rely on user-supplied file extensions.
    """
    if header.startswith(b"%PDF-"):
        return "pdf"
    if header.startswith(b"MZ"):
        return "pe"
    if header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "office_legacy"  # OLE2 (doc, xls, ppt)
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06") or header.startswith(b"PK\x07\x08"):
        return "zip_based"      # zip, docx, xlsx, pptx, jar
    if header.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if header.startswith(b"\x1f\x8b"):
        return "gzip"
    if header.startswith(b"{\\rtf"):
        return "rtf"
    try:
        header[:512].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        pass
    return "binary_unknown"


def _extract_urls_from_bytes(data: bytes) -> List[str]:
    """Finds HTTP/HTTPS URLs embedded in raw binary or text data."""
    text = data.decode("latin-1", errors="ignore")
    raw_urls = re.findall(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', text)
    cleaned = []
    for u in raw_urls:
        u = u.rstrip('.,;)\'">]')
        if len(u) > 9 and u not in cleaned:
            cleaned.append(u)
    return cleaned[:30]


# ── PDF Static Analyzer ─────────────────────────────────────────────────────────

def analyze_pdf_content(file_path: Path) -> Dict[str, Any]:
    """
    Statically analyzes PDF structure for active code and embedded lures without executing it.
    """
    findings: Dict[str, Any] = {
        "has_javascript": False,
        "has_open_action": False,
        "has_embedded_files": False,
        "has_launch_action": False,
        "has_uri_action": False,
        "extracted_urls": [],
        "suspicious_indicators": [],
    }

    with open(file_path, "rb") as f:
        data = f.read(5 * 1024 * 1024)  # Read first 5MB for structural inspection

    # Search for PDF object keys
    if re.search(rb'/JavaScript\b|/JS\b', data, re.IGNORECASE):
        findings["has_javascript"] = True
        findings["suspicious_indicators"].append("Contains embedded executable JavaScript actions")

    if re.search(rb'/OpenAction\b', data, re.IGNORECASE):
        findings["has_open_action"] = True
        findings["suspicious_indicators"].append("Configured with automatic execution trigger (OpenAction)")

    if re.search(rb'/AA\b', data, re.IGNORECASE):
        findings["suspicious_indicators"].append("Contains automated response action triggers")

    if re.search(rb'/Launch\b', data, re.IGNORECASE):
        findings["has_launch_action"] = True
        findings["suspicious_indicators"].append("Attempts to launch an external application or process")

    if re.search(rb'/EmbeddedFiles\b', data, re.IGNORECASE):
        findings["has_embedded_files"] = True
        findings["suspicious_indicators"].append("Contains hidden embedded file attachments")

    if re.search(rb'/URI\b', data, re.IGNORECASE):
        findings["has_uri_action"] = True

    # Extract URLs from PDF
    findings["extracted_urls"] = _extract_urls_from_bytes(data)

    return findings


# ── Office Document Analyzer ───────────────────────────────────────────────────

def analyze_office_content(file_path: Path, is_openxml: bool) -> Dict[str, Any]:
    """
    Statically inspects Microsoft Office files (DOC, DOCX, XLS, XLSX) for VBA macros and external template injections.
    """
    findings: Dict[str, Any] = {
        "has_macros": False,
        "has_autoexec": False,
        "has_external_relationships": False,
        "extracted_urls": [],
        "suspicious_indicators": [],
    }

    if is_openxml:
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                namelist = z.namelist()
                # Check for VBA project binary
                vba_files = [n for n in namelist if "vbaProject.bin" in n or "vba" in n.lower()]
                if vba_files:
                    findings["has_macros"] = True
                    findings["suspicious_indicators"].append("Document contains embedded macro code (VBA project)")

                    # Check for autoexec keywords inside vbaProject.bin
                    for vf in vba_files:
                        try:
                            vba_bytes = z.read(vf)
                            if re.search(rb'AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec', vba_bytes, re.IGNORECASE):
                                findings["has_autoexec"] = True
                                findings["suspicious_indicators"].append("Macro is configured to execute automatically when opened")
                        except Exception:
                            pass

                # Check external relationships (remote template injection attack vector)
                rel_files = [n for n in namelist if n.endswith(".rels")]
                for rf in rel_files:
                    try:
                        rel_content = z.read(rf).decode("utf-8", errors="ignore")
                        if 'TargetMode="External"' in rel_content:
                            findings["has_external_relationships"] = True
                            ext_urls = re.findall(r'Target="(https?://[^"]+)"', rel_content)
                            for u in ext_urls:
                                if u not in findings["extracted_urls"]:
                                    findings["extracted_urls"].append(u)
                            findings["suspicious_indicators"].append("Document references external remote resources or templates")
                    except Exception:
                        pass
        except Exception:
            pass
    else:
        # Legacy OLE2 file (.doc, .xls)
        try:
            import olefile
            if olefile.isOleFile(str(file_path)):
                with olefile.OleFileIO(str(file_path)) as ole:
                    streams = ole.listdir()
                    stream_paths = ["/".join(s) for s in streams]
                    if any("vba" in s.lower() or "macros" in s.lower() for s in stream_paths):
                        findings["has_macros"] = True
                        findings["suspicious_indicators"].append("Legacy Office document contains embedded VBA macros")
        except Exception:
            pass

        # Fallback binary scan for OLE
        with open(file_path, "rb") as f:
            ole_bytes = f.read(5 * 1024 * 1024)
            if re.search(rb'AutoOpen|AutoExec|Document_Open|Workbook_Open', ole_bytes, re.IGNORECASE):
                findings["has_macros"] = True
                findings["has_autoexec"] = True
                findings["suspicious_indicators"].append("Contains automatic execution instructions")
            findings["extracted_urls"] = _extract_urls_from_bytes(ole_bytes)

    return findings


# ── Archive Analyzer ───────────────────────────────────────────────────────────

def analyze_archive_content(file_path: Path) -> Dict[str, Any]:
    """
    Inspects ZIP archive contents without extracting files to the operating system.
    Detects executable payloads, double extensions, and zip-bomb decompression threats.
    """
    findings: Dict[str, Any] = {
        "total_files": 0,
        "dangerous_files": [],
        "is_zip_bomb": False,
        "has_double_extensions": False,
        "extracted_urls": [],
        "suspicious_indicators": [],
    }

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            infolist = z.infolist()
            findings["total_files"] = len(infolist)
            total_uncompressed = 0
            total_compressed = 0

            for info in infolist:
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
                fname = info.filename.lower()

                # Extension check
                _, ext = os.path.splitext(fname)
                if ext in DANGEROUS_EXTENSIONS:
                    findings["dangerous_files"].append(info.filename)
                    findings["suspicious_indicators"].append(f"Archive contains executable or script payload ({info.filename})")

                # Double extension check (e.g. statement.pdf.exe)
                if re.search(r'\.(pdf|doc|docx|xlsx|jpg|png|txt)\.(exe|scr|bat|cmd|vbs|js|hta|iso)$', fname):
                    findings["has_double_extensions"] = True
                    findings["suspicious_indicators"].append(f"Disguised file with spoofed double extension ({info.filename})")

            # Zip bomb check
            if total_uncompressed > _MAX_ZIP_EXTRACTED_SIZE:
                findings["is_zip_bomb"] = True
                findings["suspicious_indicators"].append("Decompressed payload exceeds safety threshold (potential archive bomb)")
            elif total_compressed > 0 and (total_uncompressed / total_compressed) > _MAX_ZIP_RATIO:
                findings["is_zip_bomb"] = True
                findings["suspicious_indicators"].append("Extreme compression ratio detected (potential decompression bomb)")

    except Exception:
        findings["suspicious_indicators"].append("Malformed or corrupted archive structure")

    return findings


# ── Executable (PE) Static Analyzer ────────────────────────────────────────────

def analyze_pe_content(file_path: Path) -> Dict[str, Any]:
    """
    Statically analyzes Windows Portable Executable (PE) files without executing them.
    Examines imports, section entropy, and potential packing indicators.
    """
    findings: Dict[str, Any] = {
        "is_packed": False,
        "suspicious_api_calls": [],
        "high_entropy_sections": [],
        "extracted_urls": [],
        "suspicious_indicators": [
            "Attachment is an executable program (.exe/.dll) rather than a safe document"
        ],
    }

    try:
        import pefile
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories()

        # Check section entropy for packing/cryptor signs
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            entropy = section.get_entropy()
            if entropy > 7.1:
                findings["high_entropy_sections"].append(f"{sec_name} ({entropy:.2f})")
                findings["is_packed"] = True

        if findings["is_packed"]:
            findings["suspicious_indicators"].append("Contains obfuscated or packed executable code sections")

        # Inspect imported APIs
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="ignore")
                        for category, apis in SUSPICIOUS_PE_APIS.items():
                            if api_name in apis:
                                findings["suspicious_api_calls"].append(f"{api_name} [{category}]")

        if findings["suspicious_api_calls"]:
            findings["suspicious_indicators"].append(
                f"Binary imports sensitive memory or process manipulation routines ({len(findings['suspicious_api_calls'])} detected)"
            )
        pe.close()
    except Exception:
        # Fallback binary entropy calculation
        with open(file_path, "rb") as f:
            raw = f.read(2 * 1024 * 1024)
            ent = calculate_entropy(raw)
            if ent > 7.2:
                findings["is_packed"] = True
                findings["suspicious_indicators"].append("File content exhibits very high entropy (likely encrypted or packed)")
            findings["extracted_urls"] = _extract_urls_from_bytes(raw)

    return findings


# ── Unified Attachment Security Pipeline ─────────────────────────────────────────

def analyze_attachment_file(file_path: Path, filename: str) -> Dict[str, Any]:
    """
    Main quarantine static-analysis entrypoint.
    Inspects the file, extracts URLs, flags indicators, and builds user-facing explanation.
    """
    size_bytes = file_path.stat().st_size
    if size_bytes > _MAX_FILE_SIZE:
        return {
            "file_name": filename,
            "file_size_bytes": size_bytes,
            "risk": "High-risk",
            "is_suspicious": True,
            "explanation": f"File size ({size_bytes // (1024*1024)}MB) exceeds maximum safe upload limit of 25MB.",
            "safety_advice": ["Do not inspect or open this oversized file.", "Verify the origin with the sender through an alternate channel."],
            "evidence": ["Exceeds safety ingestion threshold (oversized)"],
            "url_analysis": [],
            "findings": {"file_type": "oversized"},
        }

    # SHA-256 calculation
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256_hash.update(chunk)
    file_sha256 = sha256_hash.hexdigest()

    # Read header for magic bytes
    with open(file_path, "rb") as f:
        header = f.read(2048)

    real_type = detect_real_file_type(header)
    _, ext = os.path.splitext(filename.lower())

    type_mismatch = False
    if real_type == "pe" and ext not in (".exe", ".dll", ".scr"):
        type_mismatch = True
    elif real_type == "pdf" and ext != ".pdf":
        type_mismatch = True

    # Run specialized static analyzer
    extracted_urls: List[str] = []
    indicators: List[str] = []
    specific_findings: Dict[str, Any] = {"real_file_type": real_type, "detected_extension": ext}

    if type_mismatch:
        indicators.append(f"Mismatched file structure: appears to be a binary executable disguised with a '{ext}' extension")

    if real_type == "pdf":
        pdf_res = analyze_pdf_content(file_path)
        indicators.extend(pdf_res["suspicious_indicators"])
        extracted_urls.extend(pdf_res["extracted_urls"])
        specific_findings.update(pdf_res)

    elif real_type == "pe":
        pe_res = analyze_pe_content(file_path)
        indicators.extend(pe_res["suspicious_indicators"])
        extracted_urls.extend(pe_res["extracted_urls"])
        specific_findings.update(pe_res)

    elif real_type == "office_legacy":
        off_res = analyze_office_content(file_path, is_openxml=False)
        indicators.extend(off_res["suspicious_indicators"])
        extracted_urls.extend(off_res["extracted_urls"])
        specific_findings.update(off_res)

    elif real_type == "zip_based":
        # Check if Office OpenXML (docx/xlsx) or general archive
        is_office_xml = ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm")
        if is_office_xml:
            off_res = analyze_office_content(file_path, is_openxml=True)
            indicators.extend(off_res["suspicious_indicators"])
            extracted_urls.extend(off_res["extracted_urls"])
            specific_findings.update(off_res)
        else:
            arch_res = analyze_archive_content(file_path)
            indicators.extend(arch_res["suspicious_indicators"])
            extracted_urls.extend(arch_res["extracted_urls"])
            specific_findings.update(arch_res)

    else:
        # Text or generic binary
        with open(file_path, "rb") as f:
            raw = f.read(2 * 1024 * 1024)
            extracted_urls.extend(_extract_urls_from_bytes(raw))

    # Evaluate any extracted URLs using the extended URL analyzer
    url_analysis_results = [analyze_url_extended(u) for u in extracted_urls[:10]]
    suspicious_urls = [u for u in url_analysis_results if u.get("is_suspicious")]
    if suspicious_urls:
        indicators.append(f"Contains {len(suspicious_urls)} link(s) matching known phishing or suspicious destination patterns")

    # Determine overall Risk Level
    is_high_risk = (
        real_type == "pe" or
        type_mismatch or
        specific_findings.get("has_javascript") or
        specific_findings.get("has_autoexec") or
        specific_findings.get("is_zip_bomb") or
        len(specific_findings.get("dangerous_files", [])) > 0 or
        len(suspicious_urls) > 0
    )

    is_suspicious = (
        not is_high_risk and (
            specific_findings.get("has_macros") or
            specific_findings.get("has_open_action") or
            specific_findings.get("has_external_relationships") or
            len(extracted_urls) > 0 or
            len(indicators) > 0
        )
    )

    if is_high_risk:
        risk = "High-risk"
    elif is_suspicious:
        risk = "Suspicious"
    else:
        risk = "Genuine"

    # Human-friendly explanation (no cybersecurity tool names)
    if risk == "High-risk":
        explanation = (
            f"This attachment '{filename}' exhibits critical security hazards: "
            + "; ".join(indicators[:3])
            + ". Opening this file may compromise your device or expose credentials."
        )
        safety_advice = [
            "Do not open, decompress, or permit active content in this attachment.",
            "Delete or quarantine the file immediately.",
            "If this arrived via email or SMS, independently contact the alleged sender using verified contact info.",
        ]
    elif risk == "Suspicious":
        explanation = (
            f"This attachment '{filename}' contains non-standard components: "
            + ("; ".join(indicators[:2]) if indicators else "embedded links or external references were detected")
            + ". Exercise caution before opening."
        )
        safety_advice = [
            "Do not enable macros or approve permission prompts if requested by the document.",
            "Inspect any destination links before clicking them.",
            "Verify with the sender that they intended to send this file format.",
        ]
    else:
        explanation = (
            f"Static inspection of '{filename}' found standard document formatting without active scripts, embedded executable code, or suspicious links."
        )
        safety_advice = [
            "Standard security hygiene applies.",
            "Only open attachments from verified senders you trust.",
        ]

    return {
        "file_name": filename,
        "file_size_bytes": size_bytes,
        "sha256": file_sha256,
        "real_file_type": real_type,
        "risk": risk,
        "is_suspicious": (risk != "Genuine"),
        "evidence": indicators,
        "url_analysis": url_analysis_results,
        "findings": specific_findings,
        "explanation": explanation,
        "safety_advice": safety_advice,
        "disclaimer": "This is a static security assessment, not a guarantee of file safety.",
    }
