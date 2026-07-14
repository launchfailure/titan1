"""Deterministic LOLBin identification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Pattern, Sequence

from .models import LOLBinFinding


@dataclass(frozen=True)
class LOLBinRule:
    name: str
    executable: str
    pattern: Pattern[str]
    technique_ids: Sequence[str]
    suspicious_terms: Sequence[str] = ()

    def evaluate(self, nodes: Iterable[Mapping[str, Any]]) -> LOLBinFinding | None:
        node_ids: List[Any] = []
        matched_terms: List[str] = []
        confidence = 0.0

        for node in nodes:
            text = " ".join(
                str(node.get(key) or "")
                for key in ("content_preview", "preview", "artifact_name", "method")
            )
            if not self.pattern.search(text):
                continue
            node_ids.append(node.get("id"))
            confidence = max(confidence, 0.55)
            lowered = text.lower()
            for term in self.suspicious_terms:
                if term.lower() in lowered:
                    matched_terms.append(term)
                    confidence = min(0.95, confidence + 0.08)

        if not node_ids:
            return None
        return LOLBinFinding(
            name=self.name,
            executable=self.executable,
            technique_ids=list(self.technique_ids),
            confidence=confidence,
            node_ids=node_ids,
            matched_terms=matched_terms,
        )


def _exe(name: str) -> Pattern[str]:
    return re.compile(
        rf"(?i)(?<![A-Za-z0-9_]){re.escape(name)}(?:\.exe)?(?![A-Za-z0-9_])"
    )


DEFAULT_LOLBIN_RULES = (
    LOLBinRule("PowerShell", "powershell.exe", _exe("powershell"), ("T1059.001",), ("-enc", "encodedcommand", "downloadstring", "invoke-expression", "iex")),
    LOLBinRule("Command Shell", "cmd.exe", _exe("cmd"), ("T1059.003",), ("/c", "/k")),
    LOLBinRule("Mshta", "mshta.exe", _exe("mshta"), ("T1218.005",), ("javascript:", "vbscript:", "http://", "https://")),
    LOLBinRule("Rundll32", "rundll32.exe", _exe("rundll32"), ("T1218.011",), ("javascript:", "url.dll", "shell32.dll")),
    LOLBinRule("Regsvr32", "regsvr32.exe", _exe("regsvr32"), ("T1218.010",), ("/s", "/u", "/i:", "scrobj.dll")),
    LOLBinRule("Msiexec", "msiexec.exe", _exe("msiexec"), ("T1218.007",), ("/i", "/q", "http://", "https://")),
    LOLBinRule("InstallUtil", "installutil.exe", _exe("installutil"), ("T1218.004",), ("/logfile=", "/logtoconsole=false")),
    LOLBinRule("WMIC", "wmic.exe", _exe("wmic"), ("T1047",), ("process call create", "/node:")),
    LOLBinRule("WScript", "wscript.exe", _exe("wscript"), ("T1059.005",), (".vbs", ".vbe")),
    LOLBinRule("CScript", "cscript.exe", _exe("cscript"), ("T1059.005",), (".vbs", ".js", "//e:")),
    LOLBinRule("Schtasks", "schtasks.exe", _exe("schtasks"), ("T1053.005",), ("/create", "/run", "/sc")),
    LOLBinRule("Certutil", "certutil.exe", _exe("certutil"), ("T1105", "T1140"), ("-urlcache", "-decode", "-decodehex")),
    LOLBinRule("Bitsadmin", "bitsadmin.exe", _exe("bitsadmin"), ("T1105",), ("/transfer", "/addfile", "/resume")),
    LOLBinRule("MSBuild", "msbuild.exe", _exe("msbuild"), ("T1127.001",), (".csproj", ".proj", ".xml", "/p:")),
    LOLBinRule("CMSTP", "cmstp.exe", _exe("cmstp"), ("T1218.003",), ("/s", "/ns", ".inf")),
    LOLBinRule("Odbcconf", "odbcconf.exe", _exe("odbcconf"), ("T1218.008",), ("regsvr", "/a", ".dll")),
    LOLBinRule("Regsvcs", "regsvcs.exe", _exe("regsvcs"), ("T1218.009",), (".dll",)),
    LOLBinRule("Regasm", "regasm.exe", _exe("regasm"), ("T1218.009",), ("/u", ".dll")),
    LOLBinRule("Forfiles", "forfiles.exe", _exe("forfiles"), ("T1202",), ("/c", "cmd")),
    LOLBinRule("Pcalua", "pcalua.exe", _exe("pcalua"), ("T1202",), ("-a",)),
    # "hh" and "at" are everyday words, so unlike the rules above these two
    # require the literal ".exe" suffix to avoid firing on ordinary prose
    # ("hh:mm", "look at the file").
    LOLBinRule("HTML Help", "hh.exe", re.compile(r"(?i)(?<![A-Za-z0-9_])hh\.exe(?![A-Za-z0-9_])"), ("T1218.001",), ("http://", "https://", ".chm")),
    LOLBinRule("At", "at.exe", re.compile(r"(?i)(?<![A-Za-z0-9_])at\.exe(?![A-Za-z0-9_])"), ("T1053.002",), ()),
    LOLBinRule("Crontab", "crontab", _exe("crontab"), ("T1053.003",), ("curl", "wget", "| crontab")),
)


def identify_lolbins(
    nodes: Iterable[Mapping[str, Any]],
    rules: Sequence[LOLBinRule] = DEFAULT_LOLBIN_RULES,
) -> List[LOLBinFinding]:
    findings = [
        finding
        for rule in rules
        if (finding := rule.evaluate(nodes)) is not None
    ]
    return sorted(findings, key=lambda item: (-item.confidence, item.executable))
