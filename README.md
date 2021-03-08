# 2021-march-exchange

Info
====
Et repo som samler litt nyttig informasjon ifm. Microsoft Exchange-sårbarheter og angrepskampanje JAN - MAR 2021.


Ekstern informasjon
======
https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/


Scripts / verktøy
=======

Nettverksskanning
-------
nmap-script fra Microsoft for å oppdage sårbar Exchange:
https://github.com/microsoft/CSS-Exchange/blob/main/Security/http-vuln-cve2021-26855.nse

Quickfix
------
PowerShell-script for å mitigere SSRF-sårbarheten som ble brukt i angrepskampanjen:
https://github.com/microsoft/CSS-Exchange/releases/latest/download/BackendCookieMitigation.ps1
OBS: Vi anbefaler oppdatering så fort det lar seg gjøre. Dette er et sikringstiltak fram til oppdatering er gjennomført.

Webshellsøk
------
PowerShell-script fra CERT-LV for å oppdage webshells: 
https://github.com/cert-lv/exchange_webshell_detection/blob/main/detect_webshells.ps1

Powershell-onliner for å oppdage nylig opprettede .aspx-filer, som ofte vil være tilfellet for webshell:
```powershell
Get-ChildItem -Path 'C:' -Filter *.aspx -Recurse -ErrorAction SilentlyContinue | ? {$_.LastWriteTime -gt (Get-Date).AddDays(-10)}
```
Generelt kan vi anbefale å varsle om nyopprettede/endrede filer i web-mapper (både aspx-filer og andre) og sammenlikne dette med endringskalender for virksomheten. Nye filer og endringer i filer som ikke ellers kan forklares bør undersøkes grundig. Om man f.eks. har Sysmon installert og config justert riktig kan man søke etter Eventcode 11 og filepath C:\inetpub\wwwroot*.

Loggsøk, passorddumper, zip-filer
------
PowerShell-script for å søke etter indikatorer på utnyttelse av CVE-2021-26855, 26858, 26857 og 27065, samt etter LSASS-dumps:
https://github.com/microsoft/CSS-Exchange/blob/main/Security/Test-ProxyLogon.ps1

Powershell-online for å søke på tvers av logger, eksempelvis for requestIDer eller IP-adresser:
```powershell
Get-ChildItem -Recurse -Path "C:\Program Files\Microsoft\Exchange Server\V15\Logging" -Filter '*.log' | % { $content = get-content -path $_.fullname | select-string 'søkestreng'; if($content) {write-host $_.fullname; $content; write-output '-----'   }  }
```

Nye brukere
------
PowerShell-script for å hente ut brukere opprettet siste 30 dager (hentet fra https://community.spiceworks.com/topic/581589-active-directory-powershell-script-list-all-newly-created-users-for-a-specific-m):
```powershell
Import-Module -Name ActiveDirectory
$date = (get-Date).tostring()
$month = (Get-Date).AddDays(-30)
$ADuserInmonth = Get-ADUser -Filter * -Properties whencreated | where { $_.whenCreated -ge $month } | select name,whenCreated
```


Stand-alone malwarescanner fra Microsoft:
------
https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download
Instruksjoner for bruk av Microsoft Safety Scanner:
https://github.com/microsoft/CSS-Exchange/blob/main/Security/Defender-MSERT-Guidance.md
