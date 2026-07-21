"""Trusted, hash-bound assurance provider adapters.

Providers are optional and explicit. Titan passes an evidence path to a
configured executable without a shell, validates the resulting JSON, and
stores it atomically under the evidence SHA-256. The sample is never executed
by this module; a sandbox command must submit it to a separately managed VM.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any, Mapping, MutableMapping, Sequence


_MAX_PROVIDER_OUTPUT = 1024 * 1024


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _root_sha256(report: Mapping[str, Any]) -> str | None:
    nodes = report.get("nodes")
    if not isinstance(nodes, list):
        return None
    for node in nodes:
        if isinstance(node, Mapping) and node.get("parent") is None:
            value = str(node.get("sha256") or "").lower()
            return value if len(value) == 64 else None
    return None


def _provider_environment() -> dict[str, str]:
    """Retain only process-launch essentials instead of leaking all secrets."""
    allowed = {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment["TITAN_ASSURANCE_PROVIDER"] = "1"
    return environment


def _validate_attestation(
    kind: str, value: Any, expected_sha256: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("provider output must be a JSON object")
    claimed = str(value.get("sample_sha256") or "").lower()
    if claimed != expected_sha256:
        raise ValueError("provider output is not bound to the analyzed SHA-256")
    if str(value.get("schema_version") or "") != "1.0":
        raise ValueError("provider output uses an unsupported schema version")
    if kind == "sandbox":
        if value.get("completed") is not True:
            raise ValueError("sandbox attestation is incomplete")
        if str(value.get("isolation") or "").lower() not in {
            "vm",
            "virtual_machine",
        }:
            raise ValueError("sandbox provider did not attest VM isolation")
        if str(value.get("verdict") or "").lower() not in {
            "clean",
            "no_malicious_behavior",
            "suspicious",
            "malicious",
        }:
            raise ValueError("sandbox provider returned an unknown verdict")
    elif kind == "provenance":
        if not isinstance(value.get("trusted"), bool):
            raise ValueError(
                "provenance attestation must declare trusted true or false"
            )
        if value.get("trusted") is True and not all(
            str(value.get(field) or "").strip()
            for field in ("verification_method", "identity")
        ):
            raise ValueError("trusted provenance requires a method and identity")
    else:  # pragma: no cover - private API invariant
        raise ValueError(f"unsupported assurance provider kind: {kind}")
    return dict(value)


def _write_attestation(directory: Path, digest: str, value: Mapping[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{digest}.json"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=directory,
        prefix=f".{digest}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump(dict(value), handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    try:
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def _run_bounded_command(
    argv: Sequence[str], request: Mapping[str, Any], timeout: int
) -> tuple[int, str, str]:
    """Run an adapter without buffering untrusted output into process memory."""
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    encoded = json.dumps(dict(request), separators=(",", ":")).encode("utf-8")
    with (
        tempfile.TemporaryFile() as input_file,
        tempfile.TemporaryFile() as stdout_file,
        tempfile.TemporaryFile() as stderr_file,
    ):
        input_file.write(encoded)
        input_file.seek(0)
        process = subprocess.Popen(
            list(argv),
            stdin=input_file,
            stdout=stdout_file,
            stderr=stderr_file,
            shell=False,
            env=_provider_environment(),
            creationflags=creation_flags,
        )
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                raise TimeoutError(f"provider exceeded the {timeout}s timeout")
            if (
                os.fstat(stdout_file.fileno()).st_size > _MAX_PROVIDER_OUTPUT
                or os.fstat(stderr_file.fileno()).st_size > _MAX_PROVIDER_OUTPUT
            ):
                process.kill()
                process.wait()
                raise ValueError("provider output exceeded 1 MiB")
            time.sleep(0.01)
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if stdout_size > _MAX_PROVIDER_OUTPUT or stderr_size > _MAX_PROVIDER_OUTPUT:
            raise ValueError("provider output exceeded 1 MiB")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(stdout_size).decode("utf-8", errors="strict")
        stderr = stderr_file.read(stderr_size).decode("utf-8", errors="replace")
        return int(process.returncode or 0), stdout, stderr


class AssuranceProviderRunner:
    """Run configured sandbox/provenance adapters and record provider status."""

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = dict(config or {})
        self.timeout = max(
            1, int(self.config.get("assurance_provider_timeout_seconds", 120))
        )

    def collect(
        self,
        sample_path: Path,
        report: MutableMapping[str, Any],
        *,
        allow_external: bool = False,
    ) -> list[dict[str, Any]]:
        sample_path = sample_path.expanduser().resolve()
        digest = _file_sha256(sample_path)
        report_hash = _root_sha256(report)
        if report_hash and report_hash != digest:
            raise ValueError("assurance provider input does not match the report root")

        statuses: list[dict[str, Any]] = []
        for kind, command_key, directory_key in (
            (
                "sandbox",
                "sandbox_provider_command",
                "sandbox_attestations_dir",
            ),
            (
                "provenance",
                "provenance_provider_command",
                "provenance_attestations_dir",
            ),
        ):
            command = self.config.get(command_key)
            if command:
                if allow_external:
                    statuses.append(
                        self._run_command(
                            kind,
                            command,
                            sample_path,
                            digest,
                            self.config.get(directory_key),
                        )
                    )
                else:
                    statuses.append(
                        self._error(kind, "provider command disabled in offline mode")
                    )

        if self.config.get("enable_authenticode_provider", False):
            statuses.append(self._run_authenticode(sample_path, digest))
        report["assurance_providers"] = statuses
        return statuses

    def _run_command(
        self,
        kind: str,
        command: Any,
        sample_path: Path,
        digest: str,
        configured_directory: Any,
    ) -> dict[str, Any]:
        if not isinstance(command, Sequence) or isinstance(command, (str, bytes)):
            return self._error(kind, "provider command must be a JSON argv array")
        argv = [
            str(token).replace("{sample}", str(sample_path)).replace("{sha256}", digest)
            for token in command
        ]
        if not argv:
            return self._error(kind, "provider command is empty")
        if not configured_directory:
            return self._error(kind, "attestation output directory is not configured")
        request = {
            "schema_version": "1.0",
            "provider_kind": kind,
            "sample_path": str(sample_path),
            "sample_sha256": digest,
        }
        try:
            return_code, stdout, stderr = _run_bounded_command(
                argv, request, self.timeout
            )
            if return_code:
                detail = stderr.strip()[:500]
                raise RuntimeError(
                    f"provider exited with status {return_code}"
                    + (f": {detail}" if detail else "")
                )
            value = _validate_attestation(kind, json.loads(stdout), digest)
            if _file_sha256(sample_path) != digest:
                raise ValueError("sample changed while the provider was running")
            destination = _write_attestation(
                Path(str(configured_directory)).expanduser(), digest, value
            )
            return {
                "kind": kind,
                "state": "completed",
                "attestation": str(destination),
            }
        except (OSError, RuntimeError, ValueError, UnicodeError) as exc:
            return self._error(kind, str(exc))

    def _run_authenticode(self, sample_path: Path, digest: str) -> dict[str, Any]:
        try:
            value = verify_authenticode(sample_path, digest, self.timeout)
            if value is None:
                return self._error(
                    "authenticode", "no valid trusted Authenticode signature was found"
                )
            if _file_sha256(sample_path) != digest:
                raise ValueError("sample changed during Authenticode verification")
            directory = self.config.get("provenance_attestations_dir")
            if not directory:
                return self._error(
                    "authenticode", "provenance attestation directory is not configured"
                )
            destination = _write_attestation(
                Path(str(directory)).expanduser(), digest, value
            )
            return {
                "kind": "authenticode",
                "state": "completed",
                "attestation": str(destination),
            }
        except (OSError, RuntimeError, ValueError) as exc:
            return self._error("authenticode", str(exc))

    @staticmethod
    def _error(kind: str, message: str) -> dict[str, Any]:
        return {"kind": kind, "state": "unavailable", "error": message[:1000]}


def verify_authenticode(
    sample_path: Path, digest: str, timeout: int = 30
) -> dict[str, Any] | None:
    """Verify Authenticode with the native trust provider or osslsigncode."""
    if os.name == "nt":
        executable = shutil.which("powershell.exe") or shutil.which("powershell")
        if not executable:
            raise RuntimeError("PowerShell is unavailable")
        script = (
            "$s=Get-AuthenticodeSignature -LiteralPath $env:TITAN_SAMPLE;"
            "[pscustomobject]@{status=[string]$s.Status;"
            "identity=[string]$s.SignerCertificate.Subject}|ConvertTo-Json -Compress"
        )
        environment = _provider_environment()
        environment["TITAN_SAMPLE"] = str(sample_path)
        completed = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=environment,
        )
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip()[:500] or "verification failed")
        value = json.loads(completed.stdout)
        if str(value.get("status") or "").lower() != "valid":
            return None
        identity = str(value.get("identity") or "").strip()
    else:
        executable = shutil.which("osslsigncode")
        if not executable:
            raise RuntimeError("osslsigncode is unavailable")
        completed = subprocess.run(
            [executable, "verify", "-in", str(sample_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=_provider_environment(),
        )
        if completed.returncode:
            return None
        identity = "Authenticode signer verified by osslsigncode"
    if not identity:
        return None
    return {
        "schema_version": "1.0",
        "sample_sha256": digest,
        "trusted": True,
        "verification_method": "authenticode",
        "identity": identity,
    }
