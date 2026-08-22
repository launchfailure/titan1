#!/usr/bin/env python3
"""Interactive, menu-driven front end for the Titan Decoder engine.

This is the friendly "just run ``titan``" experience: instead of remembering
CLI flags, the user gets a menu where they can pick a decoder (or let the engine
auto-detect), paste a test payload or point at a file, and see the decoded
result. It is a thin presentation layer over the exact same engine and decoders
the ``titan cli`` interface drives — no analysis logic lives here.

Kept dependency-light (stdlib only) and structured so the pure pieces (the
decoder registry, result formatting) are unit-testable without a real TTY, and
the loop can be driven with injected input/output streams.
"""

from __future__ import annotations

import binascii
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from . import __version__ as TITAN_VERSION
from .config import Config
from .core.engine import TitanEngine
from .core.analyzers.steganography import MediaPayloadDecoder
from .decoders.base import (
    ASN1Decoder,
    Base32Decoder,
    Base64Decoder,
    Base64UrlDecoder,
    Bz2Decoder,
    Decoder,
    GzipDecoder,
    HexDecoder,
    HTMLEntityDecoder,
    LzmaDecoder,
    OLEDecoder,
    PDFDecoder,
    PemArmorDecoder,
    QuotedPrintableDecoder,
    RecursiveBase64Decoder,
    Rot13Decoder,
    URLDecoder,
    UnicodeEscapeDecoder,
    Utf16Decoder,
    UUDecoder,
    XorDecoder,
    ZlibDecoder,
)
from .decoders.advanced import (
    Ascii85Decoder,
    Base58Decoder,
    Base91Decoder,
    BrotliDecoder,
    JavaScriptEscapeDecoder,
    PowerShellEncodedCommandDecoder,
    RawDeflateDecoder,
    ZstandardDecoder,
)
from .utils.helpers import entropy, looks_like_text, sha256

# ---------------------------------------------------------------------------
# Terminal styling (ANSI, auto-disabled when not a TTY or NO_COLOR is set)
# ---------------------------------------------------------------------------


class Style:
    """Tiny ANSI colour helper. Colours collapse to empty strings when the
    output is not an interactive terminal, or when ``NO_COLOR`` is set, so piped
    output stays clean."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def magenta(self, t: str) -> str:
        return self._wrap("35", t)


def _color_enabled(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TITAN_NO_COLOR") is not None:
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


# ---------------------------------------------------------------------------
# Decoder registry
# ---------------------------------------------------------------------------

# Reasonable cap for the one-shot single-decoder decompressors so a hostile
# "zip bomb" test payload can't exhaust memory in the interactive UI.
_MAX_DECOMPRESSED = 16 * 1024 * 1024


@dataclass(frozen=True)
class DecoderChoice:
    """A user-selectable decoder plus a short human description."""

    key: str
    label: str
    description: str
    factory: Callable[[], Decoder]


def build_decoder_registry() -> List[DecoderChoice]:
    """Return every decoder the user can pick by hand, in a friendly order.

    Optional decoders that ship disabled-by-default in the engine (they are
    normally only switched on by smart-detection) are constructed with
    ``enabled=True`` here, because the user is explicitly asking for them.
    """
    return [
        DecoderChoice(
            "base64", "Base64", "Standard Base64 (handles line wrapping)", Base64Decoder
        ),
        DecoderChoice(
            "recursive_base64",
            "Recursive Base64",
            "Repeatedly Base64-decode nested layers",
            RecursiveBase64Decoder,
        ),
        DecoderChoice(
            "base64url",
            "Base64 URL-safe",
            "URL/filename-safe Base64 alphabet",
            Base64UrlDecoder,
        ),
        DecoderChoice(
            "base32", "Base32", "RFC 4648 Base32", lambda: Base32Decoder(enabled=True)
        ),
        DecoderChoice("ascii85", "ASCII85", "Adobe ASCII85 / Base85", Ascii85Decoder),
        DecoderChoice(
            "base58", "Base58", "Labeled or strongly recognized Base58", Base58Decoder
        ),
        DecoderChoice(
            "base91", "Base91", "Labeled or strongly recognized Base91", Base91Decoder
        ),
        DecoderChoice("hex", "Hex", "Hexadecimal (e.g. 48656c6c6f)", HexDecoder),
        DecoderChoice(
            "url", "URL / percent", "URL percent-encoding (%20 etc.)", URLDecoder
        ),
        DecoderChoice(
            "html_entity",
            "HTML entities",
            "HTML entities (&amp; &#65; ...)",
            HTMLEntityDecoder,
        ),
        DecoderChoice(
            "unicode_escape",
            "Unicode escape",
            r"\uXXXX / \xXX escape sequences",
            UnicodeEscapeDecoder,
        ),
        DecoderChoice(
            "utf16", "UTF-16", "UTF-16 text (with or without BOM)", Utf16Decoder
        ),
        DecoderChoice(
            "powershell_encoded_command",
            "PowerShell EncodedCommand",
            "Decode a PowerShell -EncodedCommand argument",
            PowerShellEncodedCommandDecoder,
        ),
        DecoderChoice(
            "javascript_escape",
            "JavaScript escapes",
            "Decode %uXXXX, \\xXX, and fromCharCode",
            JavaScriptEscapeDecoder,
        ),
        DecoderChoice("rot13", "ROT13", "Caesar/ROT13 letter rotation", Rot13Decoder),
        DecoderChoice(
            "xor", "XOR (auto-key)", "Recover single/repeating-key XOR", XorDecoder
        ),
        DecoderChoice(
            "quoted_printable",
            "Quoted-Printable",
            "MIME Quoted-Printable (=3D ...)",
            lambda: QuotedPrintableDecoder(enabled=True),
        ),
        DecoderChoice(
            "uuencode",
            "UUencode",
            "Classic uuencoded data",
            lambda: UUDecoder(enabled=True),
        ),
        DecoderChoice(
            "pem",
            "PEM armor",
            "Strip PEM ----BEGIN----/----END---- armor",
            PemArmorDecoder,
        ),
        DecoderChoice(
            "gzip",
            "Gzip",
            "Gzip-compressed data",
            lambda: GzipDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "zlib",
            "Zlib",
            "Zlib/deflate-compressed data",
            lambda: ZlibDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "raw_deflate",
            "Raw DEFLATE",
            "RFC 1951 DEFLATE without a zlib wrapper",
            lambda: RawDeflateDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "brotli",
            "Brotli",
            "Explicitly labeled Brotli stream (optional dependency)",
            lambda: BrotliDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "zstandard",
            "Zstandard",
            "Zstandard frame (optional dependency)",
            lambda: ZstandardDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "bz2",
            "Bzip2",
            "Bzip2-compressed data",
            lambda: Bz2Decoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "lzma",
            "LZMA / XZ",
            "LZMA/XZ-compressed data",
            lambda: LzmaDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "pdf",
            "PDF streams",
            "Extract/inflate PDF object streams",
            lambda: PDFDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "ole",
            "OLE / CFB",
            "Parse OLE/CFB (legacy Office) streams",
            lambda: OLEDecoder(_MAX_DECOMPRESSED),
        ),
        DecoderChoice(
            "asn1",
            "ASN.1 / DER",
            "Parse ASN.1 DER structures",
            lambda: ASN1Decoder(enabled=True),
        ),
        DecoderChoice(
            "steganography_media",
            "Steganography / Media",
            "Recover hidden or appended payloads from images and media",
            lambda: MediaPayloadDecoder(_MAX_DECOMPRESSED),
        ),
    ]


# ---------------------------------------------------------------------------
# Result formatting (pure — no I/O)
# ---------------------------------------------------------------------------


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(data)


def _hexdump(data: bytes, max_bytes: int = 256) -> str:
    """Classic offset / hex / ASCII hexdump of the first ``max_bytes`` bytes."""
    out = []
    view = data[:max_bytes]
    for off in range(0, len(view), 16):
        chunk = view[off : off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<47}"
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        out.append(f"  {off:08x}  {hex_part}  {ascii_part}")
    if len(data) > max_bytes:
        out.append(f"  ... ({len(data) - max_bytes} more bytes)")
    return "\n".join(out)


def format_decode_result(
    st: Style, decoder_label: str, source_len: int, decoded: bytes, success: bool
) -> str:
    """Render a single-decoder result as a printable block."""
    lines: List[str] = []
    if not success or decoded is None:
        lines.append(st.red(f"✗ {decoder_label} could not decode this input."))
        lines.append(
            st.dim("  The bytes don't look like this format, or decoding failed.")
        )
        return "\n".join(lines)

    is_text = looks_like_text(decoded)
    lines.append(st.green(f"✓ Decoded with {decoder_label}"))
    lines.append(
        st.dim(
            f"  {source_len} byte(s) in → {len(decoded)} byte(s) out"
            f"   |  entropy {entropy(decoded):.2f}"
            f"   |  sha256 {sha256(decoded)[:16]}…"
        )
    )
    lines.append("")
    if is_text or _printable_ratio(decoded) >= 0.85:
        text = decoded.decode("utf-8", errors="replace")
        preview = text if len(text) <= 4000 else text[:4000] + "\n… (truncated)"
        lines.append(st.bold("  Decoded text:"))
        for ln in preview.splitlines() or [""]:
            lines.append("    " + ln)
    else:
        lines.append(st.bold("  Decoded bytes (hexdump):"))
        lines.append(_hexdump(decoded))
    return "\n".join(lines)


def format_engine_summary(st: Style, report: dict) -> str:
    """Render the auto-detect (full-engine) report as a readable summary."""
    lines: List[str] = []
    nodes = report.get("nodes", []) or []
    lines.append(
        st.green(f"✓ Auto-analysis complete — {len(nodes)} node(s) in the decode tree")
    )
    lines.append("")

    # Decode tree: indent by depth, show the method that produced each node.
    lines.append(st.bold("  Decode tree:"))
    for node in nodes:
        depth = int(node.get("depth", 0) or 0)
        indent = "    " + "  " * depth
        method = node.get("method") or "input"
        ctype = node.get("content_type", "?")
        dlen = node.get("decoded_length", node.get("source_length", 0))
        marker = "•" if depth else "▸"
        head = f"{indent}{marker} {st.cyan(method)}  {st.dim(f'[{ctype}, {dlen}B]')}"
        lines.append(head)
        preview = (node.get("content_preview") or "").strip()
        if preview:
            snippet = preview.replace("\n", " ")
            if len(snippet) > 88:
                snippet = snippet[:88] + "…"
            lines.append(f"{indent}    {st.dim(snippet)}")

    # IOCs, if any surfaced.
    iocs = report.get("iocs", {}) or {}
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    if total_iocs:
        lines.append("")
        lines.append(st.bold(f"  Indicators found ({total_iocs}):"))
        for kind, values in sorted(iocs.items()):
            if not values:
                continue
            shown = ", ".join(str(v) for v in values[:5])
            more = f" (+{len(values) - 5} more)" if len(values) > 5 else ""
            lines.append(f"    {st.yellow(kind)}: {shown}{more}")
    else:
        lines.append("")
        lines.append(st.dim("  No indicators (URLs/IPs/hashes/…) extracted."))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Interactive application
# ---------------------------------------------------------------------------


class InteractiveApp:
    """The menu loop. I/O is injectable so the whole thing is testable."""

    def __init__(
        self,
        input_fn: Callable[[str], str] = input,
        out=None,
        style: Optional[Style] = None,
        config: Optional[Config] = None,
    ):
        self.input_fn = input_fn
        self.out = out or sys.stdout
        self.st = style if style is not None else Style(_color_enabled(self.out))
        self.config = config or Config()
        self.registry = build_decoder_registry()
        # Session options.
        self.profile: str = "fast"  # safe | fast | full
        self.offline: bool = True
        # Aggressive auto-detect (session-only). When on, auto-detect enables the
        # opt-in decoders, searches deeper, and lowers the keep-threshold so
        # weaker/short decodes survive. It is applied per-run to the engine
        # config only — the core-engine defaults the CLI/tests rely on are never
        # touched. Baselines are captured so the toggle is fully reversible
        # regardless of how many times it's flipped in a session.
        self.aggressive: bool = False
        self._baseline_decoders = dict(self.config.get("decoders", {}) or {})
        self._baseline_min_score = self.config.get("min_score_threshold", 0.01)

    # -- low-level I/O helpers ---------------------------------------------

    def _print(self, *parts: str) -> None:
        print(*parts, file=self.out)

    def _ask(self, prompt: str) -> str:
        """Prompt for a line of input. EOF is treated as 'quit'."""
        try:
            return self.input_fn(prompt)
        except EOFError:
            raise _QuitSignal()

    # -- payload acquisition ------------------------------------------------

    def _read_payload(self) -> Optional[Tuple[bytes, int]]:
        """Ask the user for input and return ``(data, source_len)`` or ``None``.

        Offers three input styles: typed text, a hex string (handy for binary
        test vectors), or a file path.
        """
        self._print()
        self._print(self.st.bold("  How do you want to provide the input?"))
        self._print("    [1] Type/paste text")
        self._print("    [2] Enter a hex string (e.g. 48656c6c6f)")
        self._print("    [3] Load from a file")
        self._print("    [b] Back")
        choice = self._ask(self.st.cyan("  input> ")).strip().lower()

        if choice in ("b", "back", ""):
            return None

        if choice == "1":
            raw = self._ask("  Text: ")
            data = raw.encode("utf-8")
            return data, len(data)

        if choice == "2":
            raw = self._ask("  Hex: ").strip().replace(" ", "").replace("\n", "")
            try:
                data = binascii.unhexlify(raw)
            except (binascii.Error, ValueError) as e:
                self._print(self.st.red(f"  Not valid hex: {e}"))
                return None
            return data, len(data)

        if choice == "3":
            path_s = self._ask("  File path: ").strip()
            # Allow surrounding quotes pasted from a file manager / shell.
            path_s = path_s.strip("'\"")
            path = Path(os.path.expanduser(path_s))
            if not path.exists() or not path.is_file():
                self._print(self.st.red(f"  File not found: {path}"))
                return None
            try:
                data = path.read_bytes()
            except OSError as e:
                self._print(self.st.red(f"  Could not read file: {e}"))
                return None
            if not data:
                self._print(self.st.red("  File is empty."))
                return None
            return data, len(data)

        self._print(self.st.red("  Unknown choice."))
        return None

    # -- output persistence -------------------------------------------------

    def _maybe_save(self, data: bytes, prompt: str) -> None:
        """Offer to write ``data`` to a file. Blank input skips (the default)."""
        path_s = (
            self._ask(f"  {prompt} (path, or Enter to skip): ").strip().strip("'\"")
        )
        if not path_s:
            return
        path = Path(os.path.expanduser(path_s))
        try:
            if path.parent and not path.parent.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except OSError as e:
            self._print(self.st.red(f"  Could not write {path}: {e}"))
            return
        self._print(self.st.green(f"  Saved {len(data)} byte(s) → {path}"))

    # -- menu actions -------------------------------------------------------

    # Opt-in decoders that "aggressive" mode switches on for auto-detect.
    _AGGRESSIVE_DECODERS = ("base32", "uuencode", "quoted_printable", "asn1")

    def _configured_engine(self) -> TitanEngine:
        """Build an engine honouring the session's profile / aggressive options.

        Every setting is (re)applied on each call, so the resulting engine
        reflects the *current* toggle state no matter how the options were
        flipped. Aggressive settings are layered on top of the profile and are
        restored to the captured baselines when the toggle is off — so turning
        aggressive on and back off returns to exactly the normal behaviour.
        """
        cfg = self.config
        if self.profile == "safe":
            cfg.set("max_recursion_depth", 3)
            cfg.set("max_node_count", 50)
        elif self.profile == "fast":
            cfg.set("max_recursion_depth", 3)
            cfg.set("max_node_count", 50)
        elif self.profile == "full":
            cfg.set("max_recursion_depth", 8)
            cfg.set("max_node_count", 200)

        # Start decoders/threshold from the captured baseline every time.
        decoders = dict(self._baseline_decoders)
        if self.aggressive:
            for name in self._AGGRESSIVE_DECODERS:
                decoders[name] = True
            cfg.set("min_score_threshold", 0.0)
            # Deepen the search a little, but never *below* the profile's budget.
            cfg.set(
                "max_recursion_depth", max(int(cfg.get("max_recursion_depth", 5)), 6)
            )
            cfg.set("max_node_count", max(int(cfg.get("max_node_count", 100)), 200))
        else:
            cfg.set("min_score_threshold", self._baseline_min_score)
        cfg.set("decoders", decoders)

        return TitanEngine(cfg)

    def action_auto_detect(self) -> None:
        payload = self._read_payload()
        if payload is None:
            return
        data, source_len = payload
        self._print()
        mode = " [aggressive]" if self.aggressive else ""
        self._print(self.st.dim(f"  Running full engine (auto-detect){mode}…"))
        try:
            if self.offline:
                from .core.offline_guard import block_network

                with block_network():
                    report = self._configured_engine().run_analysis(data)
            else:
                report = self._configured_engine().run_analysis(data)
        except Exception as e:  # keep the UI alive on engine errors
            self._print(self.st.red(f"  Analysis failed: {e}"))
            return
        self._print()
        self._print(format_engine_summary(self.st, report))
        self._print()
        report_json = json.dumps(report, indent=2).encode("utf-8")
        self._maybe_save(report_json, "Save full JSON report to")

    def action_pick_decoder(self) -> None:
        self._print()
        self._print(self.st.bold("  Available decoders:"))
        for i, choice in enumerate(self.registry, 1):
            self._print(
                f"    {self.st.cyan(f'{i:>2}')}) {choice.label:<18} {self.st.dim(choice.description)}"
            )
        self._print("    " + self.st.dim(" b) Back"))
        sel = self._ask(self.st.cyan("  decoder> ")).strip().lower()
        if sel in ("b", "back", ""):
            return
        if not sel.isdigit() or not (1 <= int(sel) <= len(self.registry)):
            self._print(self.st.red("  Invalid selection."))
            return
        choice = self.registry[int(sel) - 1]

        payload = self._read_payload()
        if payload is None:
            return
        data, source_len = payload
        decoder = choice.factory()
        try:
            decoded, success = decoder.decode(data)
        except Exception as e:
            self._print(self.st.red(f"  Decoder raised an error: {e}"))
            return
        self._print()
        self._print(
            format_decode_result(self.st, choice.label, source_len, decoded, success)
        )
        if success and decoded:
            self._print()
            self._maybe_save(decoded, "Save decoded output to")

    def action_list_decoders(self) -> None:
        self._print()
        self._print(self.st.bold(f"  {len(self.registry)} decoders available:"))
        for choice in self.registry:
            self._print(f"    • {choice.label:<18} {self.st.dim(choice.description)}")
        self._print()
        self._print(
            self.st.dim(
                "  Tip: 'Auto-detect' chains these recursively and also runs the"
            )
        )
        self._print(self.st.dim("  ZIP/TAR/PE/ELF analyzers and IOC extraction."))

    def action_options(self) -> None:
        while True:
            self._print()
            self._print(self.st.bold("  Options"))
            self._print(
                f"    [1] Analysis profile : {self.st.cyan(self.profile)}  (safe / fast / full)"
            )
            self._print(
                f"    [2] Network           : {self.st.cyan('offline' if self.offline else 'online')}"
            )
            self._print(
                f"    [3] Aggressive auto-detect : {self.st.cyan('on' if self.aggressive else 'off')}"
                f"  {self.st.dim('(opt-in decoders, deeper search, keep weak decodes)')}"
            )
            self._print("    [b] Back")
            sel = self._ask(self.st.cyan("  options> ")).strip().lower()
            if sel in ("b", "back", ""):
                return
            if sel == "1":
                val = self._ask("    Profile (safe/fast/full): ").strip().lower()
                if val in ("safe", "fast", "full"):
                    self.profile = val
                else:
                    self._print(self.st.red("    Unknown profile."))
            elif sel == "2":
                val = self._ask("    Network (offline/online): ").strip().lower()
                if val in ("offline", "off"):
                    self.offline = True
                elif val in ("online", "on"):
                    self.offline = False
                else:
                    self._print(self.st.red("    Unknown value."))
            elif sel == "3":
                # Simple toggle. Aggressive only affects auto-detect ([1] on the
                # main menu); single-decoder mode is unchanged.
                self.aggressive = not self.aggressive
                state = "on" if self.aggressive else "off"
                self._print(
                    self.st.green(f"    Aggressive auto-detect is now {state}.")
                )
                if self.aggressive:
                    self._print(
                        self.st.dim(
                            "    Heads-up: expect more (and weaker) results — good for "
                            "hands-on testing, noisier for real triage."
                        )
                    )
            else:
                self._print(self.st.red("    Unknown choice."))

    # -- banner / menu ------------------------------------------------------

    def _banner(self) -> None:
        st = self.st
        self._print()
        self._print(
            st.cyan(st.bold("  ╔══════════════════════════════════════════════╗"))
        )
        self._print(
            st.cyan(st.bold("  ║           TITAN  DECODER  ENGINE               ║"))
        )
        self._print(
            st.cyan(st.bold(f"  ║   interactive console · v{TITAN_VERSION:<20}║"))
        )
        self._print(
            st.cyan(st.bold("  ╚══════════════════════════════════════════════╝"))
        )
        self._print(st.dim("  Decode payloads by hand or let the engine auto-detect."))

    def _menu(self) -> str:
        st = self.st
        self._print()
        self._print(st.bold("  What would you like to do?"))
        net = "offline" if self.offline else "online"
        agg = ", aggressive" if self.aggressive else ""
        self._print(
            f"    [1] {st.green('Auto-detect & decode')}   {st.dim('(run the full engine)')}"
        )
        self._print("    [2] Choose a specific decoder")
        self._print("    [3] List available decoders")
        self._print(
            f"    [4] Options {st.dim(f'(profile={self.profile}, {net}{agg})')}"
        )
        self._print("    [q] Quit")
        return self._ask(st.cyan("  titan> ")).strip().lower()

    def run(self) -> int:
        self._banner()
        try:
            while True:
                choice = self._menu()
                if choice in ("q", "quit", "exit"):
                    break
                elif choice == "1":
                    self.action_auto_detect()
                elif choice == "2":
                    self.action_pick_decoder()
                elif choice == "3":
                    self.action_list_decoders()
                elif choice == "4":
                    self.action_options()
                elif choice == "":
                    continue
                else:
                    self._print(self.st.red("  Unknown option — type 1, 2, 3, 4 or q."))
        except (_QuitSignal, KeyboardInterrupt):
            self._print()
        self._print(self.st.dim("  Bye."))
        return 0


class _QuitSignal(Exception):
    """Internal signal to unwind the loop on EOF (Ctrl+D)."""


def main(argv: Optional[List[str]] = None) -> int:
    """Console entry point for the ``titan`` command."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="titan",
        description=(
            "Interactive Titan console. Run with no arguments for the "
            "menu-driven experience; use 'titan cli' for the scriptable CLI."
        ),
    )
    parser.add_argument("--version", action="version", version=f"titan {TITAN_VERSION}")
    # Unknown arguments are tolerated (and ignored) so `python -m` shims and
    # wrappers keep working, and there's room to grow without breaking callers.
    parser.parse_known_args(argv)

    # The enhanced console subclasses InteractiveApp; the base app remains the
    # stable, tested core the upgrade layers presentation on top of.
    from .ui.console import EnhancedInteractiveApp

    return EnhancedInteractiveApp().run()


if __name__ == "__main__":
    sys.exit(main())
