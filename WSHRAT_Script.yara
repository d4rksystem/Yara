rule WSHRAT_Script {
   meta:
      description = "Detects WSHRAT malware scripts and related files. This has been tested, but use at your own risk!"
      author = "Kyle Cucci (@d4rksystem)
      date = "2021-06-17"
      
   strings:
   $a1 = "WSHRAT" ascii
   $a2 = "function getCountry()" ascii
   $a3 = "function getHost()" ascii
   $a4 = "getHost = phost" ascii
   $a5 = "HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\run\\" ascii
   $a6 = "wscript.exe" ascii

   condition: 
      filesize < 250000 and filesize > 100000
      and (3 of ($a*))
}
