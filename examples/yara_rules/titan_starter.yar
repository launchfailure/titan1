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
