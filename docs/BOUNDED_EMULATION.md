# Bounded emulation

Titan includes two small interpreters for deterministic deobfuscation. They do
not invoke a JavaScript runtime, map executable memory, execute native code, or
expose filesystem, network, process, clock, environment, or random APIs.
Unsupported behavior stops interpretation rather than falling through to a
host capability.

## Constant JavaScript evaluator

`JavaScriptEmulation` evaluates only:

- quoted string and integer literals;
- parentheses and `+` for constant addition/concatenation;
- previously resolved `var`, `let`, or `const` names;
- `String.fromCharCode`, `atob`, `decodeURIComponent`, and `unescape`;
- a top-level `eval(constant_expression)` whose value is returned as text but
  never executed.

Source and output default to 1 MiB, a script is capped at 64 statements, and
each expression has a 4,096-step budget. Property access, loops, callbacks,
objects, dynamic indexing, imports, browser APIs, and Node APIs are rejected.
The evaluator is also wired into the Script analyzer as
`javascript_emulated.txt`.

## x86 constant emulator

`X86ShellcodeEmulation` is a 32-bit x86 foundation for constant propagation
and stack-string recovery. It supports a deliberately small register-only
subset: immediate/register push and pop, immediate moves, EAX arithmetic/XOR
and compare, register XOR, NOP, bounded relative branches/calls, and return.

Memory operands halt with `memory_access_blocked`; interrupts, breakpoints,
and extended opcode tables halt with
`system_or_extended_instruction_blocked`. Unknown and truncated instructions
also halt. Execution defaults to 4,096 instructions, 256 nested calls, a 1 MiB
source/stack ceiling, and entry offset zero. The analyzer requires multiple
immediate-push markers before it runs, emits a deterministic register/halt
report, and places recovered printable stack strings back into Titan's graph
for IOC extraction.

This is intentionally not a compatibility claim with Unicorn or a malware
sandbox. Additional instructions must land with positive, adversarial,
budget-exhaustion, and blocked-I/O tests before entering the whitelist.
