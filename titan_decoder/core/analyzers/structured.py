"""Bounded static analyzers for common delivery and container formats."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
import html
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tempfile
from typing import Any, Iterable
import zipfile

from .base import Analyzer
from ...decoders.advanced import (
    JavaScriptEscapeDecoder,
    PowerShellEncodedCommandDecoder,
)
from ...decoders.base import UnicodeEscapeDecoder


def _safe_name(value: str, fallback: str = "artifact.bin") -> str:
    value = value.replace("\\", "/").rsplit("/", 1)[-1]
    value = "".join(char for char in value if char.isalnum() or char in "._- ")
    return value[:160] or fallback


def _safe_archive_path(value: str) -> PurePosixPath | None:
    """Return a normalized relative archive path or reject unsafe members."""
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts:
        return None
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path


class _Collector:
    def __init__(self, max_artifacts: int, max_total: int, max_item: int):
        self.max_artifacts = max(1, max_artifacts)
        self.max_total = max(1, max_total)
        self.max_item = max(1, max_item)
        self.total = 0
        self.items: list[tuple[str, bytes]] = []
        self.names: set[str] = set()

    def add(self, name: str, content: bytes) -> bool:
        if not content or len(self.items) >= self.max_artifacts:
            return False
        content = content[: self.max_item]
        if self.total + len(content) > self.max_total:
            return False
        candidate = _safe_name(name)
        stem, dot, suffix = candidate.partition(".")
        index = 2
        while candidate.lower() in self.names:
            candidate = f"{stem}_{index}{dot}{suffix}" if dot else f"{stem}_{index}"
            index += 1
        self.names.add(candidate.lower())
        self.items.append((candidate, content))
        self.total += len(content)
        return True


class EmailAnalyzer(Analyzer):
    """Parse RFC 5322/MIME mail and expose bodies and attachments."""

    _HEADER = re.compile(
        rb"(?im)^(?:from|to|subject|date|message-id|mime-version|content-type):"
    )

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))

    @property
    def name(self) -> str:
        return "Email"

    def can_analyze(self, data: bytes) -> bool:
        header = data[: 64 * 1024]
        return bool(
            b"\n\n" in header.replace(b"\r\n", b"\n") and self._HEADER.search(header)
        )

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        try:
            message = BytesParser(policy=policy.default).parsebytes(data)
        except Exception:
            return []

        collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
        summary: dict[str, Any] = {
            "analyzer": "email",
            "subject": str(message.get("subject", ""))[:4096],
            "from": str(message.get("from", ""))[:4096],
            "to": str(message.get("to", ""))[:4096],
            "date": str(message.get("date", ""))[:256],
            "message_id": str(message.get("message-id", ""))[:512],
            "parts": [],
            "attachments": [],
        }
        parts: Iterable[Any] = message.walk() if message.is_multipart() else (message,)
        body_index = 0
        attachment_index = 0
        for part in parts:
            if part.is_multipart():
                continue
            content_type = str(part.get_content_type())
            filename = part.get_filename()
            disposition = str(part.get_content_disposition() or "")
            summary["parts"].append(
                {
                    "content_type": content_type,
                    "filename": str(filename or "")[:512],
                    "disposition": disposition,
                }
            )
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if not isinstance(payload, bytes) or not payload:
                continue
            if (
                filename
                or disposition == "attachment"
                or not content_type.startswith("text/")
            ):
                attachment_index += 1
                safe = _safe_name(str(filename or f"attachment_{attachment_index}.bin"))
                if collector.add(f"email_{safe}", payload):
                    summary["attachments"].append(safe)
                continue
            body_index += 1
            charset = part.get_content_charset() or "utf-8"
            try:
                normalized = payload.decode(charset, errors="replace").encode("utf-8")
            except LookupError:
                normalized = payload.decode("utf-8", errors="replace").encode("utf-8")
            collector.add(f"email_body_{body_index}.txt", normalized)

        encoded_summary = json.dumps(summary, indent=2, sort_keys=True).encode("utf-8")
        collector.items.insert(
            0, ("email_summary.json", encoded_summary[: self.max_item])
        )
        return collector.items[: self.max_artifacts]


class OfficeAnalyzer(Analyzer):
    """Inspect OOXML packages, relationships, macros, and embedded objects."""

    _OFFICE_PREFIXES = ("word/", "xl/", "ppt/")
    _REL_TARGET = re.compile(
        rb"(?is)<Relationship\b[^>]*\bTarget\s*=\s*['\"]([^'\"]+)['\"][^>]*>"
    )
    _TAG = re.compile(rb"<[^>]{1,8192}>")

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))
        self.max_ratio = int(config.get("max_compression_ratio", 100))

    @property
    def name(self) -> str:
        return "OfficeOOXML"

    def can_analyze(self, data: bytes) -> bool:
        if not data.startswith(b"PK\x03\x04"):
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()[:4096]
        except (OSError, zipfile.BadZipFile):
            return False
        return "[Content_Types].xml" in names and any(
            name.startswith(self._OFFICE_PREFIXES) for name in names
        )

    def _safe_infos(self, archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
        output: list[zipfile.ZipInfo] = []
        total = 0
        for info in archive.infolist()[:4096]:
            if info.is_dir() or info.flag_bits & 0x1:
                continue
            if info.file_size > self.max_item:
                continue
            if (
                info.compress_size
                and info.file_size / info.compress_size > self.max_ratio
            ):
                continue
            if total + info.file_size > self.max_total:
                break
            output.append(info)
            total += info.file_size
        return output

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
        summary: dict[str, Any] = {
            "analyzer": "office_ooxml",
            "package_type": "unknown",
            "macro_present": False,
            "embedded_objects": [],
            "external_relationships": [],
            "suspicious_members": [],
        }
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = self._safe_infos(archive)
                names = {info.filename for info in infos}
                if any(name.startswith("word/") for name in names):
                    summary["package_type"] = "word"
                elif any(name.startswith("xl/") for name in names):
                    summary["package_type"] = "excel"
                elif any(name.startswith("ppt/") for name in names):
                    summary["package_type"] = "powerpoint"

                for info in infos:
                    lowered = info.filename.lower()
                    interesting = (
                        lowered.endswith("vbaproject.bin")
                        or "/embeddings/" in lowered
                        or lowered.endswith(".rels")
                        or lowered.endswith(
                            ("document.xml", "workbook.xml", "presentation.xml")
                        )
                    )
                    if not interesting:
                        continue
                    try:
                        content = archive.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue
                    if lowered.endswith("vbaproject.bin"):
                        summary["macro_present"] = True
                        summary["suspicious_members"].append(info.filename)
                        collector.add("office_vbaProject.bin", content)
                    elif "/embeddings/" in lowered:
                        summary["embedded_objects"].append(info.filename)
                        collector.add(f"office_{_safe_name(info.filename)}", content)
                    elif lowered.endswith(".rels"):
                        for match in self._REL_TARGET.finditer(
                            content[: self.max_item]
                        ):
                            target = html.unescape(
                                match.group(1).decode("utf-8", errors="replace")
                            )
                            if "://" in target or target.lower().startswith(
                                ("file:", "\\\\")
                            ):
                                summary["external_relationships"].append(target[:4096])
                        collector.add(f"office_{_safe_name(info.filename)}", content)
                    else:
                        text = html.unescape(
                            self._TAG.sub(b" ", content).decode(
                                "utf-8", errors="replace"
                            )
                        )
                        text = re.sub(r"\s+", " ", text).strip()
                        if text:
                            collector.add(
                                "office_document_text.txt", text.encode("utf-8")
                            )
        except (OSError, zipfile.BadZipFile):
            return []

        summary["external_relationships"] = sorted(
            set(summary["external_relationships"])
        )[:256]
        summary["embedded_objects"] = sorted(set(summary["embedded_objects"]))[:256]
        encoded = json.dumps(summary, indent=2, sort_keys=True).encode("utf-8")
        collector.items.insert(0, ("office_summary.json", encoded[: self.max_item]))
        return collector.items[: self.max_artifacts]


class ScriptAnalyzer(Analyzer):
    """Recognize and statically normalize suspicious script content."""

    _LANGUAGE_PATTERNS: dict[str, tuple[bytes, ...]] = {
        "powershell": (
            b"powershell",
            b"invoke-",
            b"new-object",
            b"$env:",
            b"-encodedcommand",
        ),
        "javascript": (
            b"<script",
            b"function ",
            b"fromcharcode",
            b"activexobject",
            b"eval(",
        ),
        "vbscript": (b"createobject(", b"wscript.", b"cscript", b"dim "),
        "batch": (b"@echo off", b"%comspec%", b"cmd.exe /c", b"setlocal"),
        "shell": (b"#!/bin/", b"curl ", b"wget ", b"chmod +x", b"/bin/sh"),
        "python": (b"import subprocess", b"os.system(", b"exec(", b"base64.b64decode"),
    }
    _FEATURES: dict[str, bytes] = {
        "download": rb"(?i)https?://|downloadstring|\biwr\b|invoke-webrequest|\bcurl\b|\bwget\b",
        "execution": rb"(?i)invoke-expression|\biex\b|eval\s*\(|exec\s*\(|createprocess|shell\s*\(",
        "persistence": rb"(?i)currentversion\\run|schtasks|crontab|startup",
        "obfuscation": rb"(?i)fromcharcode|encodedcommand|base64|%u[0-9a-f]{4}|\\x[0-9a-f]{2}",
        "credential_access": rb"(?i)lsass|mimikatz|credential|sam\\|security\\policy",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))

    @property
    def name(self) -> str:
        return "Script"

    def _languages(self, data: bytes) -> list[str]:
        lowered = data[: self.max_item].lower()
        return sorted(
            language
            for language, markers in self._LANGUAGE_PATTERNS.items()
            if sum(marker in lowered for marker in markers) >= 2
            or (language == "shell" and lowered.startswith(b"#!"))
        )

    def can_analyze(self, data: bytes) -> bool:
        if not data or len(data) > self.max_item:
            return False
        if data.lstrip().startswith(b'{\n  "analyzer": "script"'):
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return bool(self._languages(data))

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        languages = self._languages(data)
        if not languages:
            return []
        features = sorted(
            name for name, pattern in self._FEATURES.items() if re.search(pattern, data)
        )
        artifacts: list[tuple[str, bytes]] = []
        for label, decoder in (
            ("powershell_decoded.txt", PowerShellEncodedCommandDecoder()),
            ("javascript_normalized.txt", JavaScriptEscapeDecoder()),
            ("unicode_normalized.txt", UnicodeEscapeDecoder()),
        ):
            if decoder.can_decode(data):
                output, success = decoder.decode(data)
                if success and output != data:
                    artifacts.append((label, output[: self.max_item]))
        summary = {
            "analyzer": "script",
            "languages": languages,
            "features": features,
            "deobfuscated_artifacts": [name for name, _ in artifacts],
            "execution_performed": False,
        }
        return [
            (
                "script_summary.json",
                json.dumps(summary, indent=2, sort_keys=True).encode(),
            ),
            *artifacts,
        ]


class LnkAnalyzer(Analyzer):
    """Parse Windows Shell Link metadata and recover path-like strings."""

    _CLSID = bytes.fromhex("0114020000000000c000000000000046")
    _ASCII = re.compile(rb"[\x20-\x7e]{4,4096}")
    _UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,2048}")

    @property
    def name(self) -> str:
        return "WindowsLNK"

    def can_analyze(self, data: bytes) -> bool:
        return (
            len(data) >= 76
            and data[:4] == b"L\x00\x00\x00"
            and data[4:20] == self._CLSID
        )

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        flags, attributes = struct.unpack_from("<II", data, 20)
        file_size, icon_index, show_command = struct.unpack_from("<III", data, 52)
        strings = {
            match.group().decode("ascii", errors="replace")
            for match in self._ASCII.finditer(data[: 4 << 20])
        }
        strings.update(
            match.group().decode("utf-16-le", errors="replace")
            for match in self._UTF16.finditer(data[: 4 << 20])
        )
        interesting = sorted(
            value[:4096]
            for value in strings
            if "\\" in value
            or "://" in value
            or value.lower().endswith(
                (".exe", ".dll", ".ps1", ".js", ".vbs", ".bat", ".cmd")
            )
        )[:256]
        summary = {
            "analyzer": "windows_lnk",
            "link_flags": f"0x{flags:08x}",
            "file_attributes": f"0x{attributes:08x}",
            "target_file_size": file_size,
            "icon_index": icon_index,
            "show_command": show_command,
            "strings": interesting,
            "execution_performed": False,
        }
        return [
            (
                "lnk_metadata.json",
                json.dumps(summary, indent=2, sort_keys=True).encode(),
            )
        ]


class OptionalArchiveAnalyzer(Analyzer):
    """Extract 7z, RAR, ISO, and CAB members with optional libraries."""

    _SEVEN_ZIP = b"7z\xbc\xaf'\x1c"
    _RAR = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")
    _CAB = b"MSCF"

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))
        self.max_ratio = int(config.get("max_compression_ratio", 100))

    @property
    def name(self) -> str:
        return "OptionalArchive"

    def can_analyze(self, data: bytes) -> bool:
        return bool(
            data.startswith((self._SEVEN_ZIP, *self._RAR, self._CAB))
            or (len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001")
        )

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if data.startswith(self._SEVEN_ZIP):
            return self._seven_zip(data)
        if data.startswith(self._RAR):
            return self._rar(data)
        if data.startswith(self._CAB):
            return self._cab(data)
        if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
            return self._iso(data)
        return []

    def _cab(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            from cabarchive import CabArchive  # type: ignore[import-not-found]

            archive = CabArchive(data)
            collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
            for name in sorted(archive):
                item = archive[name]
                content = bytes(item.buf)
                if len(content) <= self.max_item:
                    collector.add(_safe_name(str(name)), content)
            return collector.items
        except Exception:
            return []

    def _seven_zip(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            import py7zr  # type: ignore[import-not-found]

            with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as archive:
                selected: list[tuple[str, PurePosixPath]] = []
                selected_total = 0
                for info in sorted(archive.list(), key=lambda item: item.filename):
                    relative = _safe_archive_path(str(info.filename))
                    declared_size = int(info.uncompressed or 0)
                    compressed_size = int(info.compressed or 0)
                    if (
                        relative is None
                        or info.is_directory
                        or info.is_symlink
                        or declared_size <= 0
                        or declared_size > self.max_item
                        or selected_total + declared_size > self.max_total
                        or (
                            compressed_size
                            and declared_size / compressed_size > self.max_ratio
                        )
                    ):
                        continue
                    selected.append((str(info.filename), relative))
                    selected_total += declared_size
                    if len(selected) >= self.max_artifacts:
                        break

                if not selected:
                    return []

                collector = _Collector(
                    self.max_artifacts, self.max_total, self.max_item
                )
                with tempfile.TemporaryDirectory(prefix="titan-7z-") as directory:
                    archive.extract(
                        path=directory,
                        targets=[name for name, _ in selected],
                    )
                    root = Path(directory).resolve()
                    for name, relative in selected:
                        target = root.joinpath(*relative.parts)
                        if target.is_symlink():
                            continue
                        resolved = target.resolve()
                        if root not in resolved.parents or not resolved.is_file():
                            continue
                        with resolved.open("rb") as stream:
                            content = stream.read(self.max_item + 1)
                        if len(content) <= self.max_item:
                            collector.add(_safe_name(name), content)
                return collector.items
        except Exception:
            return []

    def _rar(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            import rarfile  # type: ignore[import-not-found]

            collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
            with rarfile.RarFile(io.BytesIO(data)) as archive:
                for info in archive.infolist()[: self.max_artifacts * 4]:
                    if info.isdir() or info.file_size > self.max_item:
                        continue
                    if (
                        info.compress_size
                        and info.file_size / info.compress_size > self.max_ratio
                    ):
                        continue
                    collector.add(_safe_name(info.filename), archive.read(info))
            return collector.items
        except Exception:
            return []

    def _iso(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            import pycdlib  # type: ignore[import-not-found]

            image = pycdlib.PyCdlib()
            image.open_fp(io.BytesIO(data))
            collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
            try:
                for directory, _, files in image.walk(iso_path="/"):
                    for entry in files:
                        parent = str(directory).rstrip("/")
                        path = f"{parent}/{entry}"
                        record: Any = image.get_record(iso_path=path)
                        declared_size = int(record.data_length)
                        if (
                            declared_size <= 0
                            or declared_size > self.max_item
                            or collector.total + declared_size > self.max_total
                        ):
                            continue
                        output = io.BytesIO()
                        image.get_file_from_iso_fp(output, iso_path=path)
                        content = output.getvalue()
                        if len(content) <= self.max_item:
                            collector.add(_safe_name(path), content)
                        if len(collector.items) >= self.max_artifacts:
                            return collector.items
            finally:
                image.close()
            return collector.items
        except Exception:
            return []
