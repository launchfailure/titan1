import json

import pytest

from titan_decoder.config import Config
from titan_decoder.core.analyzers.emulation import X86ShellcodeEmulationAnalyzer
from titan_decoder.core.emulation import (
    EmulationLimitError,
    JavaScriptConstantEvaluator,
    X86ConstantEmulator,
)
from titan_decoder.core.engine import TitanEngine
from titan_decoder.decoders.advanced import JavaScriptEmulationDecoder


def test_javascript_constant_evaluator_supports_closed_deobfuscation_subset():
    evaluator = JavaScriptConstantEvaluator()
    result = evaluator.evaluate(
        "String.fromCharCode(104,116,116,112) + "
        "decodeURIComponent('%3a%2f%2fjs.example%2fgate')"
    )
    assert result == "http://js.example/gate"
    assert evaluator.evaluate("atob('Y2FsYygp')") == "calc()"


@pytest.mark.parametrize(
    "expression",
    [
        "fetch('https://example.test')",
        "require('fs')",
        "process.exit()",
        "unknownVariable",
    ],
)
def test_javascript_evaluator_rejects_io_and_unknown_capabilities(expression):
    with pytest.raises(ValueError):
        JavaScriptConstantEvaluator().evaluate(expression)


def test_javascript_evaluator_enforces_step_and_output_budgets():
    with pytest.raises(EmulationLimitError, match="budget"):
        JavaScriptConstantEvaluator(max_steps=3).evaluate("'a'+'b'+'c'")
    with pytest.raises(EmulationLimitError, match="output"):
        JavaScriptConstantEvaluator(max_output=3).evaluate("'ab'+'cd'")


def test_javascript_emulation_decoder_resolves_variables_without_host_execution():
    decoder = JavaScriptEmulationDecoder()
    source = (
        b"var scheme=String.fromCharCode(104,116,116,112);"
        b"var target=scheme+decodeURIComponent('%3a%2f%2fstage.example%2fa');"
        b"eval(target)"
    )
    output, success = decoder.decode(source)
    assert success
    assert output == b"http://stage.example/a"
    assert decoder.decode(b"eval(fetch('https://example.test'))") == (
        b"eval(fetch('https://example.test'))",
        False,
    )


def _push_string_shellcode() -> bytes:
    return b"".join(
        (
            b"\x68com\x00",
            b"\x68vil.",
            b"\x68://e",
            b"\x68http",
            b"\xcd\x80",
        )
    )


def test_x86_emulator_recovers_stack_string_and_blocks_system_calls():
    result = X86ConstantEmulator().run(_push_string_shellcode())
    assert result.stack.startswith(b"http://evil.com\x00")
    assert result.halted == "system_or_extended_instruction_blocked"
    assert result.steps == 5


def test_x86_emulator_enforces_instruction_budget_on_loop():
    result = X86ConstantEmulator(max_steps=12).run(b"\xeb\xfe")
    assert result.steps == 12
    assert result.halted == "instruction_budget"


def test_shellcode_analyzer_emits_bounded_metadata_and_ioc_artifact():
    analyzer = X86ShellcodeEmulationAnalyzer()
    artifacts = dict(analyzer.analyze(_push_string_shellcode()))
    metadata = json.loads(artifacts["x86_emulation.json"])
    assert metadata["io_performed"] is False
    assert metadata["halted"] == "system_or_extended_instruction_blocked"
    assert artifacts["x86_emulated_strings.txt"] == b"http://evil.com"


def test_engine_registers_emulators_and_extracts_emulated_ioc():
    engine = TitanEngine(Config())
    assert {decoder.name for decoder in engine.decoders} >= {"JavaScriptEmulation"}
    assert {analyzer.name for analyzer in engine.analyzers} >= {
        "X86ShellcodeEmulation"
    }
    report = engine.run_analysis(_push_string_shellcode())
    assert "http://evil.com" in report["iocs"]["urls"]
