rule originbotnet_stealer {
    meta:
    	author = "Kyle Cucci (d@rksystem)"
	description = "Detects OriginBotnet stealer malware. OriginBotnet is a lightwiehgt, modular offshoot of AgentTelsa."
   	last_updated = "05.01.24"
	confidence = "High"

    strings:
    	$high_conf_1 = "X-KEY" wide nocase fullword
    	$high_conf_2 = "OriginBotnet" ascii wide nocase fullword

    	$med_conf_1 = "UpdateBotResponse" ascii wide fullword
    	$med_conf_2 = "UpdateBotRequest" ascii wide fullword
    	$med_conf_3 = "get_Antivirus" ascii wide fullword nocase
    	$med_conf_4 = "CmdExecuteResultRequest" ascii wide fullword

    	$low_conf_1 = "<Antivirus>k__BackingField" ascii wide fullword
    	$low_conf_2 = "<Username>k__BackingField" ascii wide fullword
    	$low_conf_3 = "<TenantId>k__BackingField" ascii wide fullword
    	$low_conf_4 = "<Success>k__BackingField" ascii wide fullword
    	$low_conf_5 = "<OsName>k__BackingField" ascii wide fullword
    	$low_conf_6 = "<Nation>k__BackingField" ascii wide fullword
    	$low_conf_7 = "<Gpu>k__BackingField" ascii wide fullword

    condition:
    	(uint16(0) == 0x5A4D) and
    	(filesize > 10000 and filesize < 400000) and
    	( 1 of ($high_conf * ) and 
    	( (1 of ($med_conf * ) or (5 of ($low_conf_ * ))) ) )
}
