"""Small, deterministic interpreters used for bounded static deobfuscation.

Neither interpreter invokes host code, performs I/O, or exposes an operating
system API. Unknown syntax/opcodes stop evaluation instead of being guessed.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import cast
from urllib.parse import unquote


class EmulationLimitError(ValueError):
    """Raised when an interpreter exhausts a configured resource budget."""


class JavaScriptConstantEvaluator:
    """Evaluate a strict subset of side-effect-free JavaScript expressions."""

    _TOKEN = re.compile(
        r"\s*(?:(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
        r"(?P<number>0[xX][0-9a-fA-F]+|\d+)|(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)|"
        r"(?P<punct>[+(),]))"
    )
    _FUNCTIONS = {"String.fromCharCode", "atob", "decodeURIComponent", "unescape"}

    def __init__(self, max_steps: int = 2000, max_output: int = 1024 * 1024):
        self.max_steps = max_steps
        self.max_output = max_output
        self.steps = 0
        self.tokens: list[tuple[str, str]] = []
        self.position = 0
        self.variables: dict[str, str | int] = {}

    def _step(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise EmulationLimitError("JavaScript instruction budget exhausted")

    def _bounded(self, value: str | int) -> str | int:
        if (
            isinstance(value, str)
            and len(value.encode("utf-8", errors="replace")) > self.max_output
        ):
            raise EmulationLimitError("JavaScript output budget exhausted")
        return value

    def _tokenize(self, expression: str) -> list[tuple[str, str]]:
        tokens = []
        cursor = 0
        while cursor < len(expression):
            match = self._TOKEN.match(expression, cursor)
            if match is None:
                raise ValueError("unsupported JavaScript syntax")
            kind = next(
                name for name, value in match.groupdict().items() if value is not None
            )
            tokens.append((kind, match.group(kind)))
            cursor = match.end()
            if len(tokens) > self.max_steps:
                raise EmulationLimitError("JavaScript token budget exhausted")
        return tokens

    @staticmethod
    def _string(token: str) -> str:
        quote = token[0]
        body = token[1:-1]

        # Decode only JavaScript's common literal escapes. Avoid Python eval.
        def replace(match: re.Match[str]) -> str:
            value = match.group(1)
            simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v"}
            if value in simple:
                return simple[value]
            if value.startswith("x"):
                return chr(int(value[1:], 16))
            if value.startswith("u"):
                code = int(value[1:], 16)
                if 0xD800 <= code <= 0xDFFF:
                    raise ValueError("surrogate literal is unsupported")
                return chr(code)
            return value if value in ("\\", quote, "'", '"') else "\\" + value

        return re.sub(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)", replace, body)

    def evaluate(
        self, expression: str, variables: dict[str, str | int] | None = None
    ) -> str | int:
        self.steps = 0
        self.variables = dict(variables or {})
        self.tokens = self._tokenize(expression.strip())
        self.position = 0
        value = self._addition()
        if self.position != len(self.tokens):
            raise ValueError("trailing JavaScript syntax")
        return self._bounded(value)

    def _peek(self, value: str | None = None) -> bool:
        if self.position >= len(self.tokens):
            return False
        return value is None or self.tokens[self.position][1] == value

    def _take(self, value: str | None = None) -> tuple[str, str]:
        self._step()
        if not self._peek(value):
            raise ValueError("unexpected JavaScript token")
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _addition(self) -> str | int:
        value = self._primary()
        while self._peek("+"):
            self._take("+")
            right = self._primary()
            value = (
                value + right
                if isinstance(value, int) and isinstance(right, int)
                else str(value) + str(right)
            )
            value = self._bounded(value)
        return value

    def _primary(self) -> str | int:
        if self._peek("("):
            self._take("(")
            value = self._addition()
            self._take(")")
            return value
        kind, token = self._take()
        if kind == "string":
            return self._string(token)
        if kind == "number":
            return int(token, 0)
        if kind != "name":
            raise ValueError("unsupported JavaScript primary")
        if self._peek("("):
            if token not in self._FUNCTIONS:
                raise ValueError(f"function is not allowed: {token}")
            self._take("(")
            arguments: list[str | int] = []
            if not self._peek(")"):
                while True:
                    arguments.append(self._addition())
                    if not self._peek(","):
                        break
                    self._take(",")
            self._take(")")
            return self._call(token, arguments)
        if token not in self.variables:
            raise ValueError(f"unknown variable: {token}")
        return self.variables[token]

    def _call(self, name: str, arguments: list[str | int]) -> str:
        self._step()
        if name == "String.fromCharCode":
            if len(arguments) > 4096 or any(
                not isinstance(value, int) or not 0 <= value <= 0xFFFF
                for value in arguments
            ):
                raise ValueError("invalid fromCharCode arguments")
            return self._bounded("".join(chr(cast(int, value)) for value in arguments))  # type: ignore[return-value]
        if len(arguments) != 1 or not isinstance(arguments[0], str):
            raise ValueError("function requires one string")
        value = arguments[0]
        if name == "atob":
            try:
                decoded = base64.b64decode(value, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError("invalid atob input") from error
            result = decoded.decode("latin-1")
        else:
            result = unquote(value.replace("%u", "\\u"))
            if name == "unescape":
                result = re.sub(
                    r"\\u([0-9a-fA-F]{4})",
                    lambda match: chr(int(match.group(1), 16)),
                    result,
                )
        return self._bounded(result)  # type: ignore[return-value]


@dataclass(frozen=True)
class X86EmulationResult:
    steps: int
    halted: str
    instruction_pointer: int
    registers: dict[str, int]
    stack: bytes


class X86ConstantEmulator:
    """Emulate a no-memory-I/O subset of 32-bit x86 constant operations."""

    _REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")

    def __init__(self, max_steps: int = 4096, max_stack: int = 1024 * 1024):
        self.max_steps = max_steps
        self.max_stack = max_stack

    @staticmethod
    def _read(code: bytes, offset: int, size: int, signed: bool = False) -> int:
        if offset < 0 or size > len(code) - offset:
            raise ValueError("truncated instruction")
        return int.from_bytes(code[offset : offset + size], "little", signed=signed)

    def run(self, code: bytes, entry: int = 0) -> X86EmulationResult:
        registers = {name: 0 for name in self._REGISTERS}
        stack = bytearray()
        call_stack: list[int] = []
        ip = entry
        steps = 0
        zero = False
        halted = "instruction_budget"

        def push(value: int) -> None:
            if len(stack) + 4 > self.max_stack:
                raise EmulationLimitError("x86 stack budget exhausted")
            stack[:0] = (value & 0xFFFFFFFF).to_bytes(4, "little")

        while steps < self.max_steps:
            if not 0 <= ip < len(code):
                halted = "instruction_pointer_out_of_range"
                break
            steps += 1
            opcode = code[ip]
            try:
                if opcode == 0x90:
                    ip += 1
                elif opcode == 0x68:
                    push(self._read(code, ip + 1, 4))
                    ip += 5
                elif opcode == 0x6A:
                    push(self._read(code, ip + 1, 1, signed=True))
                    ip += 2
                elif 0xB8 <= opcode <= 0xBF:
                    registers[self._REGISTERS[opcode - 0xB8]] = self._read(
                        code, ip + 1, 4
                    )
                    ip += 5
                elif 0x50 <= opcode <= 0x57:
                    push(registers[self._REGISTERS[opcode - 0x50]])
                    ip += 1
                elif 0x58 <= opcode <= 0x5F:
                    if len(stack) < 4:
                        halted = "stack_underflow"
                        break
                    registers[self._REGISTERS[opcode - 0x58]] = int.from_bytes(
                        stack[:4], "little"
                    )
                    del stack[:4]
                    ip += 1
                elif opcode in (0x05, 0x2D, 0x35, 0x3D):
                    immediate = self._read(code, ip + 1, 4)
                    current = registers["eax"]
                    if opcode == 0x05:
                        result = current + immediate
                    elif opcode == 0x2D:
                        result = current - immediate
                    elif opcode == 0x35:
                        result = current ^ immediate
                    else:
                        result = current - immediate
                    zero = (result & 0xFFFFFFFF) == 0
                    if opcode != 0x3D:
                        registers["eax"] = result & 0xFFFFFFFF
                    ip += 5
                elif opcode in (0x31, 0x33):
                    modrm = self._read(code, ip + 1, 1)
                    if modrm < 0xC0:
                        halted = "memory_access_blocked"
                        break
                    left = (modrm >> 3) & 7 if opcode == 0x31 else modrm & 7
                    right = modrm & 7 if opcode == 0x31 else (modrm >> 3) & 7
                    name = self._REGISTERS[left]
                    registers[name] ^= registers[self._REGISTERS[right]]
                    zero = registers[name] == 0
                    ip += 2
                elif opcode in (0x74, 0x75, 0xEB):
                    displacement = self._read(code, ip + 1, 1, signed=True)
                    taken = (
                        opcode == 0xEB
                        or (opcode == 0x74 and zero)
                        or (opcode == 0x75 and not zero)
                    )
                    ip = ip + 2 + displacement if taken else ip + 2
                elif opcode in (0xE8, 0xE9):
                    displacement = self._read(code, ip + 1, 4, signed=True)
                    target = ip + 5 + displacement
                    if opcode == 0xE8:
                        if len(call_stack) >= 256:
                            raise EmulationLimitError("x86 call-depth budget exhausted")
                        call_stack.append(ip + 5)
                    ip = target
                elif opcode == 0xC3:
                    if not call_stack:
                        halted = "return"
                        break
                    ip = call_stack.pop()
                elif opcode in (0xCD, 0xCC) or opcode == 0x0F:
                    halted = "system_or_extended_instruction_blocked"
                    break
                else:
                    halted = f"unsupported_opcode:0x{opcode:02x}"
                    break
            except ValueError:
                halted = "truncated_instruction"
                break
        return X86EmulationResult(steps, halted, ip, dict(registers), bytes(stack))
