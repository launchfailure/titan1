from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple
import zipfile
import tarfile
import io
import re
import struct

from ...utils.helpers import entropy, looks_like_zip


class Analyzer(ABC):
    """Base class for all analyzers."""

    @abstractmethod
    def can_analyze(self, data: bytes) -> bool:
        """Check if this analyzer can handle the data."""
        pass

    @abstractmethod
    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze the data and return list of (name, content) tuples."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass


class ZipAnalyzer(Analyzer):
    """ZIP file analyzer with comprehensive safety checks.

    Extraction is sequential and in archive order: the source is an in-memory
    BytesIO, so threads add no I/O parallelism (only GIL contention) while
    making result order — and therefore node ordering in reports —
    nondeterministic.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_files = self.config.get("max_zip_files", 25)
        self.max_total_size = self.config.get(
            "max_zip_total_size", 10 * 1024 * 1024
        )  # 10MB
        self.max_file_size = self.config.get(
            "max_zip_file_size", 50 * 1024 * 1024
        )  # 50MB per file
        self.max_compression_ratio = self.config.get(
            "max_compression_ratio", 100
        )  # 100:1 max

    def can_analyze(self, data: bytes) -> bool:
        return looks_like_zip(data)

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze ZIP file with safety checks."""
        final_extracted: List[Tuple[str, bytes]] = []
        total_size = 0

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                # Pre-scan for safety issues
                safe_files = self._pre_scan_zip(z)
                if not safe_files:
                    return []  # No safe files found

                extracted = self._extract_sequential(z, safe_files)

                # Apply final size limits and path sanitization
                for filename, content in extracted:
                    if len(final_extracted) >= self.max_files:
                        break

                    content_size = len(content)
                    if content_size > self.max_file_size:
                        continue
                    if total_size + content_size > self.max_total_size:
                        break

                    # Path traversal protection
                    safe_filename = self._sanitize_filename(filename)
                    final_extracted.append((safe_filename, content))
                    total_size += content_size

        except Exception:
            # Invalid ZIP or other error
            pass

        return final_extracted

    def _extract_sequential(
        self, zip_file: zipfile.ZipFile, safe_files: List[str]
    ) -> List[Tuple[str, bytes]]:
        """Extract files sequentially."""
        extracted = []
        for filename in safe_files:
            try:
                content = zip_file.read(filename)
                extracted.append((filename, content))
            except Exception:
                # Skip files that can't be read
                continue
        return extracted

    def _pre_scan_zip(self, zip_file: zipfile.ZipFile) -> List[str]:
        """Pre-scan ZIP contents for safety issues. Returns list of safe filenames."""
        safe_files = []
        # Track the running total incrementally. Recomputing
        # ``sum(getinfo(f).file_size ...)`` on every iteration made this O(n^2):
        # a small crafted archive with many tiny entries (which never trip the
        # total-size cap) turned pre-scan into a multi-minute CPU hang.
        current_safe_size = 0

        for info in zip_file.infolist():
            # Skip directories
            if info.is_dir():
                continue

            # Check for path traversal attacks
            if ".." in info.filename or info.filename.startswith("/"):
                continue

            # Check compression ratio (zip bomb detection)
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > self.max_compression_ratio:
                    # Suspicious compression ratio - likely zip bomb
                    continue

            # Check for unusually large uncompressed files
            if info.file_size > self.max_file_size:
                continue

            # Check for files that would make total size too large
            if current_safe_size + info.file_size > self.max_total_size:
                continue

            safe_files.append(info.filename)
            current_safe_size += info.file_size

        return safe_files

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues."""
        import os

        # Remove path separators and normalize
        safe_name = os.path.basename(filename)

        # Remove any remaining dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._- ")

        # Ensure it's not empty
        if not safe_name:
            safe_name = "extracted_file"

        return safe_name

    @property
    def name(self) -> str:
        return "ZIP"


class TarAnalyzer(Analyzer):
    """TAR file analyzer with comprehensive safety checks.

    Extraction is sequential: tarfile.TarFile shares one seekable file object
    with no internal locking, so concurrent extractfile() reads can interleave
    seeks and silently corrupt extracted content (unlike zipfile, tarfile is
    not thread-safe for reads).
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_files = self.config.get("max_tar_files", 25)
        self.max_total_size = self.config.get(
            "max_tar_total_size", 10 * 1024 * 1024
        )  # 10MB
        self.max_file_size = self.config.get(
            "max_tar_file_size", 50 * 1024 * 1024
        )  # 50MB per file
        self.max_compression_ratio = self.config.get(
            "max_compression_ratio", 100
        )  # 100:1 max

    def can_analyze(self, data: bytes) -> bool:
        # The ustar magic lives at offset 257 of the 512-byte tar header. Both
        # the POSIX ("ustar\x00") and GNU ("ustar  ") variants begin with
        # b"ustar" there, so match that prefix to cover both.
        return len(data) >= 262 and data[257:262] == b"ustar"

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze TAR file with safety checks."""
        final_extracted: List[Tuple[str, bytes]] = []
        total_size = 0

        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                # Pre-scan for safety issues
                safe_members = self._pre_scan_tar(t)
                if not safe_members:
                    return []  # No safe files found

                extracted = self._extract_sequential(t, safe_members)

                # Apply final size limits and path sanitization
                for member, content in extracted:
                    if len(final_extracted) >= self.max_files:
                        break

                    content_size = len(content)
                    if content_size > self.max_file_size:
                        continue
                    if total_size + content_size > self.max_total_size:
                        break

                    # Path traversal protection
                    safe_filename = self._sanitize_filename(member.name)
                    final_extracted.append((safe_filename, content))
                    total_size += content_size

        except Exception:
            # Invalid TAR or other error
            pass

        return final_extracted

    def _extract_sequential(
        self, tar_file: tarfile.TarFile, safe_members: List[tarfile.TarInfo]
    ) -> List[Tuple[tarfile.TarInfo, bytes]]:
        """Extract files sequentially."""
        extracted = []
        for member in safe_members:
            try:
                content = tar_file.extractfile(member).read()
                extracted.append((member, content))
            except Exception:
                # Skip files that can't be read
                continue
        return extracted

    def _pre_scan_tar(self, tar_file: tarfile.TarFile) -> List[tarfile.TarInfo]:
        """Pre-scan TAR contents for safety issues. Returns list of safe TarInfo objects."""
        safe_members = []
        # Incremental running total; recomputing ``sum(m.size ...)`` per member
        # was O(n^2) and let a many-entry archive hang pre-scan.
        current_safe_size = 0

        for member in tar_file.getmembers():
            # Skip non-files
            if not member.isfile():
                continue

            # Check for path traversal attacks
            if ".." in member.name or member.name.startswith("/"):
                continue

            # TAR itself doesn't compress, so there is no per-member
            # compression ratio to check — just cap the member size.
            if member.size > self.max_file_size:
                continue

            # Check for files that would make total size too large
            if current_safe_size + member.size > self.max_total_size:
                continue

            safe_members.append(member)
            current_safe_size += member.size

        return safe_members

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues."""
        import os

        # Remove path separators and normalize
        safe_name = os.path.basename(filename)

        # Remove any remaining dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._- ")

        # Ensure it's not empty
        if not safe_name:
            safe_name = "extracted_file"

        return safe_name

    @property
    def name(self) -> str:
        return "TAR"


class PEAnalyzer(Analyzer):
    """PE (Portable Executable) file metadata analyzer."""

    def can_analyze(self, data: bytes) -> bool:
        """Check if data looks like a PE file."""
        if len(data) < 64:
            return False
        # Check for MZ header
        if data[:2] != b"MZ":
            return False
        # Check for PE signature at offset from e_lfanew
        try:
            e_lfanew = struct.unpack("<I", data[60:64])[0]
            if e_lfanew + 24 > len(data):
                return False
            return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
        except Exception:
            return False

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract PE metadata without executing the file."""
        metadata = self._extract_pe_metadata(data)
        if metadata:
            # Return metadata as JSON string
            import json

            metadata_json = json.dumps(metadata, indent=2).encode("utf-8")
            return [("pe_metadata.json", metadata_json)]
        return []

    def _extract_pe_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract key metadata from PE file."""
        try:
            # DOS header
            e_lfanew = struct.unpack("<I", data[60:64])[0]

            # PE signature offset
            pe_offset = e_lfanew

            # COFF header (after PE signature)
            coff_offset = pe_offset + 4

            if coff_offset + 20 > len(data):
                return None

            # Parse COFF header
            (
                machine,
                num_sections,
                time_date_stamp,
                ptr_to_sym_table,
                num_symbols,
                size_of_opt_header,
                characteristics,
            ) = struct.unpack("<HHIIIHH", data[coff_offset : coff_offset + 20])

            # Machine types
            machine_types = {
                0x014C: "x86",
                0x0200: "IA64",
                0x8664: "x64",
                0x01C0: "ARM",
                # 0x01C4 is IMAGE_FILE_MACHINE_ARMNT (32-bit ARM Thumb-2),
                # not ARM64 (0xAA64) — mislabeling it corrupts triage.
                0x01C4: "ARM Thumb-2",
                0xAA64: "ARM64",
            }

            # Optional header
            metadata = {
                "file_type": "PE",
                "machine_type": machine_types.get(
                    machine, f"Unknown (0x{machine:04x})"
                ),
                "num_sections": num_sections,
                "time_date_stamp": time_date_stamp,
                "characteristics": f"0x{characteristics:04x}",
                "has_optional_header": size_of_opt_header > 0,
            }

            if size_of_opt_header > 0:
                opt_offset = coff_offset + 20
                if opt_offset + 24 <= len(data):
                    # Parse optional header (first 24 bytes are common)
                    (
                        magic,
                        major_linker,
                        minor_linker,
                        size_of_code,
                        size_of_init_data,
                        size_of_uninit_data,
                        entry_point,
                        base_of_code,
                    ) = struct.unpack("<HBBIIIII", data[opt_offset : opt_offset + 24])

                    metadata.update(
                        {
                            "magic": "PE32+"
                            if magic == 0x20B
                            else "PE32"
                            if magic == 0x10B
                            else f"Unknown (0x{magic:04x})",
                            "entry_point": f"0x{entry_point:08x}",
                            "size_of_code": size_of_code,
                            "size_of_init_data": size_of_init_data,
                            "size_of_uninit_data": size_of_uninit_data,
                        }
                    )

                    # For PE32, image base is a 4-byte field at offset 28.
                    if magic == 0x10B and opt_offset + 32 <= len(data):
                        image_base = struct.unpack(
                            "<I", data[opt_offset + 28 : opt_offset + 32]
                        )[0]
                        metadata["image_base"] = f"0x{image_base:08x}"

                    # For PE32+, image base is an 8-byte field at offset 24.
                    elif magic == 0x20B and opt_offset + 32 <= len(data):
                        image_base = struct.unpack(
                            "<Q", data[opt_offset + 24 : opt_offset + 32]
                        )[0]
                        metadata["image_base"] = f"0x{image_base:016x}"

                    section_offset = opt_offset + size_of_opt_header
                    sections: list[dict[str, Any]] = []
                    raw_end = 0
                    entry_section = None
                    anomalies: list[str] = []
                    for index in range(min(num_sections, 96)):
                        at = section_offset + index * 40
                        if at + 40 > len(data):
                            anomalies.append("truncated_section_table")
                            break
                        name = (
                            data[at : at + 8]
                            .split(b"\x00", 1)[0]
                            .decode("ascii", errors="replace")
                        )
                        (
                            virtual_size,
                            virtual_address,
                            raw_size,
                            raw_pointer,
                            _relocations,
                            _line_numbers,
                            _relocation_count,
                            _line_count,
                            section_flags,
                        ) = struct.unpack("<IIIIIIHHI", data[at + 8 : at + 40])
                        raw = (
                            data[raw_pointer : raw_pointer + raw_size]
                            if raw_pointer <= len(data)
                            and raw_size <= len(data) - raw_pointer
                            else b""
                        )
                        executable = bool(section_flags & 0x20000000)
                        writable = bool(section_flags & 0x80000000)
                        if executable and writable:
                            anomalies.append(f"writable_executable_section:{name}")
                        section_entropy = round(entropy(raw), 4) if raw else 0.0
                        if executable and len(raw) >= 256 and section_entropy >= 7.2:
                            anomalies.append(f"high_entropy_executable_section:{name}")
                        if (
                            virtual_address
                            <= entry_point
                            < virtual_address + max(virtual_size, raw_size, 1)
                        ):
                            entry_section = name
                        raw_end = max(raw_end, raw_pointer + raw_size)
                        sections.append(
                            {
                                "name": name,
                                "virtual_address": f"0x{virtual_address:08x}",
                                "virtual_size": virtual_size,
                                "raw_offset": raw_pointer,
                                "raw_size": raw_size,
                                "entropy": section_entropy,
                                "executable": executable,
                                "writable": writable,
                                "characteristics": f"0x{section_flags:08x}",
                            }
                        )

                    def rva_offset(rva: int) -> int | None:
                        for section in sections:
                            start = int(str(section["virtual_address"]), 16)
                            span = max(
                                int(section["virtual_size"]),
                                int(section["raw_size"]),
                                1,
                            )
                            if start <= rva < start + span:
                                offset = int(section["raw_offset"]) + rva - start
                                return offset if offset < len(data) else None
                        return rva if 0 <= rva < len(data) else None

                    directories_at = 96 if magic == 0x10B else 112
                    imports: list[str] = []
                    signature = {"present": False, "offset": 0, "size": 0}
                    if opt_offset + directories_at + 40 <= min(
                        section_offset, len(data)
                    ):
                        import_rva, import_size = struct.unpack_from(
                            "<II", data, opt_offset + directories_at + 8
                        )
                        import_at = rva_offset(import_rva) if import_size else None
                        for descriptor_index in range(256):
                            if import_at is None:
                                break
                            descriptor = import_at + descriptor_index * 20
                            if descriptor + 20 > len(data):
                                break
                            values = struct.unpack_from("<IIIII", data, descriptor)
                            if not any(values):
                                break
                            name_at = rva_offset(values[3])
                            if name_at is None:
                                continue
                            end = data.find(
                                b"\x00", name_at, min(len(data), name_at + 512)
                            )
                            if end < 0:
                                continue
                            library = data[name_at:end].decode(
                                "ascii", errors="replace"
                            )
                            if library:
                                imports.append(library)
                        certificate_at, certificate_size = struct.unpack_from(
                            "<II", data, opt_offset + directories_at + 32
                        )
                        signature = {
                            "present": bool(
                                certificate_size
                                and certificate_at < len(data)
                                and certificate_size <= len(data) - certificate_at
                            ),
                            "offset": certificate_at,
                            "size": certificate_size,
                        }

                    metadata.update(
                        {
                            "entry_point_section": entry_section,
                            "sections": sections,
                            "imports": sorted(set(imports), key=str.lower),
                            "authenticode": signature,
                            "overlay_size": max(0, len(data) - raw_end)
                            if raw_end
                            else 0,
                            "anomalies": sorted(set(anomalies)),
                        }
                    )

            return metadata

        except Exception as e:
            return {"error": f"Failed to parse PE metadata: {str(e)}"}

    @property
    def name(self) -> str:
        return "PE"


class ELFAnalyzer(Analyzer):
    """ELF (Executable and Linkable Format) file metadata analyzer."""

    def can_analyze(self, data: bytes) -> bool:
        """Check if data looks like an ELF file."""
        if len(data) < 16:
            return False
        # Check for ELF magic number
        return data[:4] == b"\x7fELF"

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract ELF metadata without executing the file."""
        metadata = self._extract_elf_metadata(data)
        if metadata:
            # Return metadata as JSON string
            import json

            metadata_json = json.dumps(metadata, indent=2).encode("utf-8")
            return [("elf_metadata.json", metadata_json)]
        return []

    def _extract_elf_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract key metadata from ELF file."""
        try:
            if len(data) < 64:
                return None

            # Parse ELF header (64 bytes)
            # e_ident (16 bytes)
            ei_class, ei_data, _ei_version, ei_osabi = (
                data[4],
                data[5],
                data[6],
                data[7],
            )

            # Class types
            class_types = {1: "32-bit", 2: "64-bit"}

            # Data encodings
            data_encodings = {1: "Little endian", 2: "Big endian"}

            # OS/ABI types
            osabi_types = {
                0: "System V",
                1: "HP-UX",
                2: "NetBSD",
                3: "Linux",
                6: "Solaris",
                9: "FreeBSD",
                12: "OpenBSD",
            }

            # Endianness and word size depend on e_ident: ELF64 uses 8-byte
            # e_entry/e_phoff/e_shoff, ELF32 uses 4-byte; ei_data selects
            # little- (1) vs big-endian (2).
            endian = ">" if ei_data == 2 else "<"
            if ei_class == 2:  # 64-bit
                header_fmt = endian + "HHIQQQIHHHHHH"
            else:  # 32-bit (and fallback)
                header_fmt = endian + "HHIIIIIHHHHHH"
            header_size = struct.calcsize(header_fmt)
            if len(data) < 16 + header_size:
                return None

            # Rest of header
            (
                e_type,
                e_machine,
                e_version,
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack(header_fmt, data[16 : 16 + header_size])

            # Object file types
            object_types = {
                1: "Relocatable",
                2: "Executable",
                3: "Shared object",
                4: "Core",
            }

            # Machine types
            machine_types = {
                0x02: "SPARC",
                0x03: "x86",
                0x08: "MIPS",
                0x14: "PowerPC",
                0x28: "ARM",
                0x32: "IA-64",
                0x3E: "x86-64",
                0xB7: "AArch64",
                0xF3: "RISC-V",
            }

            metadata = {
                "file_type": "ELF",
                "class": class_types.get(ei_class, f"Unknown ({ei_class})"),
                "data_encoding": data_encodings.get(ei_data, f"Unknown ({ei_data})"),
                "os_abi": osabi_types.get(ei_osabi, f"Unknown ({ei_osabi})"),
                "object_type": object_types.get(e_type, f"Unknown (0x{e_type:04x})"),
                "machine_type": machine_types.get(
                    e_machine, f"Unknown (0x{e_machine:04x})"
                ),
                "entry_point": f"0x{e_entry:016x}"
                if ei_class == 2
                else f"0x{e_entry:08x}",
                "program_headers_offset": e_phoff,
                "section_headers_offset": e_shoff,
                "num_program_headers": e_phnum,
                "num_section_headers": e_shnum,
                "flags": f"0x{e_flags:08x}",
            }

            sections: list[dict[str, Any]] = []
            anomalies: list[str] = []
            section_names = b""
            section_records: list[tuple[int, ...]] = []
            section_fmt = endian + ("IIQQQQIIQQ" if ei_class == 2 else "IIIIIIIIII")
            expected_section_size = struct.calcsize(section_fmt)
            if (
                e_shoff
                and e_shentsize >= expected_section_size
                and e_shnum <= 4096
                and e_shoff + e_shentsize * e_shnum <= len(data)
            ):
                for index in range(min(e_shnum, 256)):
                    at = e_shoff + index * e_shentsize
                    section_records.append(
                        struct.unpack(
                            section_fmt, data[at : at + expected_section_size]
                        )
                    )
                if 0 <= e_shstrndx < len(section_records):
                    names_record = section_records[e_shstrndx]
                    names_offset = names_record[4]
                    names_size = names_record[5]
                    if (
                        names_offset <= len(data)
                        and names_size <= len(data) - names_offset
                    ):
                        section_names = data[names_offset : names_offset + names_size]

            def section_name(offset: int) -> str:
                if offset < 0 or offset >= len(section_names):
                    return ""
                end = section_names.find(b"\x00", offset)
                if end < 0:
                    end = len(section_names)
                return section_names[offset:end].decode("utf-8", errors="replace")

            entry_section = None
            for record in section_records:
                name_at, section_type, section_flags, address, offset, size = record[:6]
                name = section_name(name_at)
                raw = (
                    data[offset : offset + size]
                    if offset <= len(data) and size <= len(data) - offset
                    else b""
                )
                writable = bool(section_flags & 0x1)
                executable = bool(section_flags & 0x4)
                section_entropy = round(entropy(raw), 4) if raw else 0.0
                if writable and executable:
                    anomalies.append(f"writable_executable_section:{name}")
                if executable and len(raw) >= 256 and section_entropy >= 7.2:
                    anomalies.append(f"high_entropy_executable_section:{name}")
                if address <= e_entry < address + max(size, 1):
                    entry_section = name
                sections.append(
                    {
                        "name": name,
                        "type": section_type,
                        "address": f"0x{address:x}",
                        "offset": offset,
                        "size": size,
                        "entropy": section_entropy,
                        "writable": writable,
                        "executable": executable,
                    }
                )

            interpreter = None
            program_fmt = endian + ("IIQQQQQQ" if ei_class == 2 else "IIIIIIII")
            expected_program_size = struct.calcsize(program_fmt)
            if (
                e_phoff
                and e_phentsize >= expected_program_size
                and e_phnum <= 4096
                and e_phoff + e_phentsize * e_phnum <= len(data)
            ):
                for index in range(min(e_phnum, 256)):
                    at = e_phoff + index * e_phentsize
                    record = struct.unpack(
                        program_fmt, data[at : at + expected_program_size]
                    )
                    program_type = record[0]
                    file_offset = record[2] if ei_class == 2 else record[1]
                    file_size = record[5] if ei_class == 2 else record[4]
                    if (
                        program_type == 3
                        and file_offset <= len(data)
                        and file_size <= len(data) - file_offset
                    ):
                        interpreter = (
                            data[file_offset : file_offset + min(file_size, 4096)]
                            .split(b"\x00", 1)[0]
                            .decode("utf-8", errors="replace")
                        )
                        break

            libraries = sorted(
                {
                    match.decode("ascii", errors="replace")
                    for match in re.findall(
                        rb"(?:lib[\w.+-]{1,128}\.so(?:\.[\w.+-]{1,64})*)",
                        data[: 32 * 1024 * 1024],
                    )
                }
            )[:256]
            if sections and not any(
                section["name"] == ".symtab" for section in sections
            ):
                anomalies.append("symbol_table_absent")
            metadata.update(
                {
                    "entry_point_section": entry_section,
                    "interpreter": interpreter,
                    "needed_libraries": libraries,
                    "sections": sections,
                    "anomalies": sorted(set(anomalies)),
                }
            )

            return metadata

        except Exception as e:
            return {"error": f"Failed to parse ELF metadata: {str(e)}"}

    @property
    def name(self) -> str:
        return "ELF"
