/*
    NKAMG Scanner 示例 YARA 规则集
    覆盖: EICAR 测试 / 可疑脚本 / 测试标记
*/

rule EICAR_Test_String
{
    meta:
        description = "EICAR 标准杀毒测试字符串"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "脚本中出现 PowerShell 下载执行链"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase ascii wide
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadFile" nocase ascii wide
        $dl3 = "IEX" ascii wide
        $net = "System.Net.WebClient" nocase ascii wide
    condition:
        $ps1 and ($dl1 or $dl2) and ($net or $dl3)
}

rule Suspicious_Base64_PowerShell
{
    meta:
        description = "编码调用 PowerShell 的常见 dropper 特征"
        severity = "high"
    strings:
        $b64a = "-enc" ascii wide nocase
        $b64b = "-encodedcommand" ascii wide nocase
        $b64c = "-e NOP" ascii wide
    condition:
        2 of ($b64a, $b64b, $b64c)
}

rule Suspicious_Macro_AutoOpen
{
    meta:
        description = "文档宏自动执行特征 (OLE 脚本)"
        severity = "medium"
    strings:
        $a1 = "AutoOpen" ascii wide
        $a2 = "Document_Open" ascii wide
        $a3 = "Workbook_Open" ascii wide
        $shell = "Shell" ascii wide
        $wscript = "WScript.Shell" ascii wide
    condition:
        1 of ($a1, $a2, $a3) and 1 of ($shell, $wscript)
}

rule NKAMG_Test_Marker
{
    meta:
        description = "NKAMG 测试标记文件 (用于验证 YARA 引擎)"
        severity = "test"
    strings:
        $marker = "NKAMG-MALWARE-TEST-MARKER"
    condition:
        $marker
}
