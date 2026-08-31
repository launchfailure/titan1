/*
  Titan starter YARA pack.

  These rules are written for Titan's per-node scanning: they assume they
  will also run against decoded and extracted artifacts, so they match
  plain-text tradecraft that is usually hidden under encoding layers in
  the raw input. Severity and ATT&CK metadata flow into Titan detections
  via the `severity` and `attack_id` meta fields.

  Usage: titan-decoder --file sample --enable-detections \
             --yara-rules examples/yara_rules
*/

rule Titan_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download cradle (IEX + web download primitives)"
        severity = "high"
        attack_id = "T1059.001"
    strings:
        $iex1 = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Net.WebClient" nocase
        $dl4 = "Invoke-WebRequest" nocase
        $dl5 = "Start-BitsTransfer" nocase
    condition:
        any of ($iex*) and any of ($dl*)
}

rule Titan_Encoded_Command_Invocation
{
    meta:
        description = "PowerShell hidden-window or encoded-command invocation flags"
        severity = "medium"
        attack_id = "T1027"
    strings:
        $host1 = "powershell" nocase
        $host2 = "pwsh" nocase
        $flag1 = "-EncodedCommand" nocase
        $flag2 = "-enc " nocase
        $flag3 = "-WindowStyle Hidden" nocase
        $flag4 = "-ExecutionPolicy Bypass" nocase
    condition:
        any of ($host*) and any of ($flag*)
}

rule Titan_Executable_In_Decoded_Content
{
    meta:
        description = "Windows PE executable recovered from analyzed content"
        severity = "medium"
        attack_id = "T1027.009"
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550
}

rule Titan_UPX_Packed_Executable
{
    meta:
        description = "UPX-packed PE executable"
        severity = "medium"
        attack_id = "T1027.002"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_sig = "UPX!"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Titan_JavaScript_Eval_Decode_Chain
{
    meta:
        description = "JavaScript eval over runtime-decoded content"
        severity = "medium"
        attack_id = "T1027.013"
    strings:
        $chain1 = "eval(String.fromCharCode" nocase
        $chain2 = "eval(unescape" nocase
        $chain3 = "eval(atob" nocase
        $chain4 = "eval(decodeURIComponent" nocase
    condition:
        any of them
}

rule Titan_Certutil_Remote_Download
{
    meta:
        description = "Certutil URL-cache download chain"
        severity = "high"
        attack_id = "T1105"
    strings:
        $host = "certutil" ascii nocase
        $urlcache = "-urlcache" ascii nocase
        $url1 = "http://" ascii nocase
        $url2 = "https://" ascii nocase
    condition:
        $host and $urlcache and any of ($url*)
}

rule Titan_MSHTA_Remote_Execution
{
    meta:
        description = "MSHTA remote or inline script execution"
        severity = "high"
        attack_id = "T1218.005"
    strings:
        $remote = /mshta(\.exe)?["']?[ \t]+https?:\/\// ascii nocase
        $inline = /mshta(\.exe)?["']?[ \t]+(javascript|vbscript):/ ascii nocase
    condition:
        any of them
}

rule Titan_Regsvr32_Remote_Scriptlet
{
    meta:
        description = "Regsvr32 remote scriptlet execution through scrobj.dll"
        severity = "high"
        attack_id = "T1218.010"
    strings:
        $host = "regsvr32" ascii nocase
        $scriptlet = "scrobj.dll" ascii nocase
        $install = "/i:" ascii nocase
        $url1 = "http://" ascii nocase
        $url2 = "https://" ascii nocase
    condition:
        $host and $scriptlet and $install and any of ($url*)
}

rule Titan_Scheduled_Task_Suspicious_Execution
{
    meta:
        description = "Logon/startup scheduled task with suspicious LOLBin execution"
        severity = "high"
        attack_id = "T1053.005"
    strings:
        $schtasks = /\bschtasks(\.exe)?\b/ ascii nocase
        $create = /\/create([ \t:]|$)/ ascii nocase
        $task_run = /\/tr([ \t:]|$)/ ascii nocase
        $trigger_cli1 = /\/sc([ \t:]+)onlogon\b/ ascii nocase
        $trigger_cli2 = /\/sc([ \t:]+)onstart\b/ ascii nocase

        $register = "Register-ScheduledTask" ascii nocase
        $task_action = "New-ScheduledTaskAction" ascii nocase
        $trigger_ps1 = "-AtLogOn" ascii nocase
        $trigger_ps2 = "-AtStartup" ascii nocase

        $host1 = "powershell" ascii nocase
        $host2 = "pwsh" ascii nocase
        $host3 = "wscript" ascii nocase
        $host4 = "cscript" ascii nocase
        $host5 = "mshta" ascii nocase
        $host6 = "regsvr32" ascii nocase

        $abuse1 = "-EncodedCommand" ascii nocase
        $abuse2 = "-WindowStyle Hidden" ascii nocase
        $abuse3 = "DownloadString" ascii nocase
        $abuse4 = "Invoke-Expression" ascii nocase
        $abuse5 = "scrobj.dll" ascii nocase
        $abuse6 = /["']?[ \t]+(javascript|vbscript):/ ascii nocase
    condition:
        (
            ($schtasks and $create and $task_run and any of ($trigger_cli*)) or
            ($register and $task_action and any of ($trigger_ps*))
        ) and any of ($host*) and any of ($abuse*)
}
