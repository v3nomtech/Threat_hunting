/*
    Rule:     Suspicious_PowerShell_InMemory_Loader
    Author:   v3nomtech
    Date:     2026-05-12
    Purpose:  Flag obfuscated PowerShell loaders that combine Base64
              decoding with reflective .NET assembly loading — a common
              pattern across Empire / Covenant / Sliver droppers.
    Notes:    Designed for hunting on dumped script content / file system
              scans, NOT for high-volume on-access scanning. Tune base64
              length threshold for your environment.
*/

rule Suspicious_PowerShell_InMemory_Loader
{
    meta:
        author      = "v3nomtech"
        description = "Obfuscated PowerShell loader with Base64 + reflective Load"
        date        = "2026-05-12"
        attack      = "T1059.001, T1027"
        confidence  = "medium"
        reference   = "https://github.com/v3nomtech/Threat_hunting"

    strings:
        $ps_header_1 = "powershell" ascii nocase
        $ps_header_2 = "pwsh"       ascii nocase

        $b64_decode_1 = "FromBase64String" ascii nocase
        $b64_decode_2 = "[Convert]::FromBase64" ascii nocase

        $reflect_1 = "System.Reflection.Assembly" ascii nocase
        $reflect_2 = "::Load("                    ascii nocase
        $reflect_3 = "Invoke-Expression"          ascii nocase
        $reflect_4 = "IEX"                        ascii nocase fullword

        $bypass_1 = "-ExecutionPolicy Bypass"  ascii nocase
        $bypass_2 = "-EncodedCommand"          ascii nocase
        $bypass_3 = "-NoProfile"               ascii nocase
        $bypass_4 = "-WindowStyle Hidden"      ascii nocase

        $long_b64 = /[A-Za-z0-9+\/]{500,}={0,2}/

    condition:
        // At least one PowerShell context indicator
        any of ($ps_header_*)
        and
        // Base64 decode call
        any of ($b64_decode_*)
        and
        // Either a reflective load OR a very long base64 blob
        (any of ($reflect_*) or $long_b64)
        and
        // At least one stealth / bypass switch
        any of ($bypass_*)
        and
        filesize < 5MB
}
