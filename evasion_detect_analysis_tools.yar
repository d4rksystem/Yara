rule evasion_detect_analysis_tools
{
    meta:
        author = "Kyle Cucci (d@rksystem)"
        description = "Triggers on possible enumeration of malware analysis tools as part of sandbox evasion and anti-analysis."
        last_updated = "2024-01-11"
        
	strings:
        $string_1 = "dnSpy" wide ascii nocase
        $string_2 = "Wireshark" wide ascii nocase
        $string_3 = "HashCalc" wide ascii nocase
        $string_4 = "FileInsight" wide ascii nocase
        $string_5 = "PDFStreamDumper" wide ascii nocase
        $string_6 = "Autoruns" wide ascii nocase
        $string_7 = "Process Hacker" wide ascii nocase
        $string_8 = "Process Monitor" wide ascii nocase
        $string_9 = "Ghidra" wide ascii nocase
        $string_10 = "x64dbg" wide ascii nocase
        $string_11 = "Hex-Rays" wide ascii nocase
        $string_12 = "IDA Pro" wide ascii nocase
        $string_13 = "PEStudio" wide ascii nocase
        $string_14 = "PE-bear" wide ascii nocase
        $string_15 = "VMware" wide ascii nocase
        $string_16 = "VirtualBox" wide ascii nocase
        $string_17 = "VBox" wide ascii nocase
        
    condition:
        (uint16(0) == 0x5A4D) and
        5 of ($string_*)
}
