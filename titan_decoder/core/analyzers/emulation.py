"""Fail-closed analyzers backed by Titan's bounded interpreters."""

from __future__ import annotations

import json
import re

from .base import Analyzer
from ..emulation import X86ConstantEmulator


class X86ShellcodeEmulationAnalyzer(Analyzer):
    """Recover immediate-push strings without permitting memory or system I/O."""

    def __init__(self, max_source: int = 1024 * 1024, max_steps: int = 4096):
        self.max_source = max_source
        self.emulator = X86ConstantEmulator(max_steps=max_steps, max_stack=max_source)

    @property
    def name(self) -> str:
        return "X86ShellcodeEmulation"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"x86_emulation.json"})

    def can_analyze(self, data: bytes) -> bool:
        if not 10 <= len(data) <= self.max_source:
            return False
        window = data[:128]
        if sum(byte in (0x68, 0x6A) for byte in window) < 2:
            return False
        result = self.emulator.run(data)
        return len(result.stack) >= 8 and bool(self._strings(result.stack))

    @staticmethod
    def _strings(data: bytes) -> list[str]:
        return sorted(
            {
                match.group().decode("ascii")
                for match in re.finditer(rb"[\x20-\x7e]{4,512}", data)
            }
        )[:128]

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        result = self.emulator.run(data)
        strings = self._strings(result.stack)
        if not strings and result.steps < 2:
            return []
        metadata = {
            "architecture": "x86-32",
            "steps": result.steps,
            "halted": result.halted,
            "instruction_pointer": result.instruction_pointer,
            "registers": {
                name: f"0x{value:08x}" for name, value in result.registers.items()
            },
            "stack_bytes": len(result.stack),
            "strings": strings,
            "io_performed": False,
        }
        artifacts = [
            (
                "x86_emulation.json",
                json.dumps(metadata, indent=2, sort_keys=True).encode(),
            )
        ]
        if strings:
            artifacts.append(("x86_emulated_strings.txt", "\n".join(strings).encode()))
        return artifacts
