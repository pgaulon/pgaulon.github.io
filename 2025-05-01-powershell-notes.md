# Windows notes

## Disks

```
Get-Volume

$items = Get-ChildItem -Path D:\Test -Recurse -Directory -Depth 1
$items | foreach { $name = $_.FullName ; $size = (Get-ChildItem $_.FullName -recurse | Where-Object {$_.PSIsContainer -eq $false} | Measure-Object -property Length -sum ).sum ; Write-Host ("{0:N2} {1}" -f ($size/1MB),$name) }
```

## Memory

```
PS C:\Users\user> Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory, TotalVisibleMemorySize
FreePhysicalMemory TotalVisibleMemorySize
------------------ ----------------------
          12159664               16666632
```

## Transferring files

```
# Windows
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Users\user\Desktop\update.ps1")) | Set-Clipboard

# MacOS
pbpaste > update.ps1.b64
base64 -d < update.ps1.b64 > update.ps1
dos2unix update.ps1
```

## List Processes

This requires PowerShell 7 to get the CommandLine attribute

```
Get-Process | Select-Object Id,CommandLine,CPU,WorkingSet64 | Format-Table
```

## IIS

```
C:\Windows\system32\inetsrv\AppCmd.exe recycle apppool "apppool_name"
```

## Privesc

### Bypass UAC with PsExec via OpenSSH

```
choco install psexec -y

PS C:\Users\user> Import-Module PSWindowsUpdate ; Get-WindowsUpdate
ComputerName Status     KB          Size Title
------------ ------     --          ---- -----
POTATO       -------    KB2267602    2GB Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (...
POTATO       -------                55KB INTEL - System - 1/1/1970 12:00:00 AM - 10.1.1.42
POTATO       -------                55KB INTEL - System - 1/1/1970 12:00:00 AM - 10.1.1.42
POTATO       -------               198KB Intel - System - 4/4/2019 12:00:00 AM - 1914.12.0.1256
POTATO       -------               631KB Intel - Net - 5/7/2019 12:00:00 AM - 12.18.9.7
POTATO       -------                 3MB Intel - net - 20.70.32.1
POTATO       -------               534KB Intel Corporation - Bluetooth - 22.200.0.2

PS C:\Users\user> psexec \\potato -s -nobanner -accepteula powershell -c 'Import-Module PSWindowsUpdate ; Install-WindowsUpdate -KBArticleID KB2267602 -AcceptAll'
X ComputerName Result     KB          Size Title
- ------------ ------     --          ---- -----
1 POTATO       Accepted   KB2267602    2GB Security Intelligence Update for Microsoft Defender Antivirus - KB2267602...
2 POTATO       Downloaded KB2267602    2GB Security Intelligence Update for Microsoft Defender Antivirus - KB2267602...
3 POTATO       Installed  KB2267602    2GB Security Intelligence Update for Microsoft Defender Antivirus - KB2267602...
```

### RunAs

```
runas.exe /user:ansible 'c:\windows\system32\windowspowershell\v1.0\powershell.exe'
```

## List Software installed

```
$machine='potato'; $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $machine) ; foreach ($key in @('','\Wow6432Node')) {$apps = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames() ; foreach ($app in $apps) { $program = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall\$app") ; $name = $program.GetValue('DisplayName') ; if ($name){ [pscustomobject]@{ComputerName = $machine; DisplayName = $name; DisplayVersion = $program.GetValue('DisplayVersion'); }}}}

(Get-WmiObject -Class Win32_OperatingSystem -ComputerName 'potato') | Select-Object -Property PSComputerName,Caption,Version
```

## List AD GPO encryption algorithm

```
Get-ADComputer -Filter * -SearchBase "OU=MyOU,OU=Servers,DC=gaulon,DC=org" | Select-Object Name

$TargetGPOName="SecureGPO" ; Get-ADOrganizationalUnit -Filter {Name -eq "MyOU"} -Properties LinkedGroupPolicyObjects | Where-Object { $_.LinkedGroupPolicyObjects -Contains $(Get-GPO -Name $TargetGPOName).Path } | Select-Object Name,@{Name='LinkedGPOName'; Expression={$TargetGPOName}}

Get-GPRegistryValue -Guid $(Get-GPO -Name "SecureGPO").id -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -ValueName "EccCurves" | Select-Object -Property Value | Format-Table -AutoSize -Wrap
Get-GPRegistryValue -Guid $(Get-GPO -Name "SecureGPO").id -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -ValueName "Functions" | Select-Object -Property Value | Format-Table -AutoSize -Wrap
```

## Audit password expiration

```
Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} -Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
```

## Event logs

```
PS C:\Windows\system32> Get-EventLog -List
PS C:\Windows\system32> Get-EventLog -LogName Application -Source "Software Protection Platform Service"
PS C:\Windows\system32> Get-EventLog -LogName "DNS Server" -After (Get-Date -Date '23/05/2026 00:00:00') -Before (Get-Date -Date '23/05/2026 11:00:00') | Where-Object {$_.Message -NotLike "*The description for Event ID*"} | Out-Host -Paging
```

## Services

```
PS C:\Windows\system32> Get-Service -Name sppsvc | Select-Object -Property *
Name                : sppsvc
RequiredServices    : {RpcSs}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : False
DisplayName         : Software Protection
DependentServices   : {}
MachineName         : .
ServiceName         : sppsvc
ServicesDependedOn  : {RpcSs}
ServiceHandle       :
Status              : Stopped
ServiceType         : Win32OwnProcess
StartType           : Automatic
Site                :
Container           :
```


## SFTP

Key permissions for using a private key with SFTP is the following

```
icacls.exe .\test.pem /inheritancelevel:d
icacls.exe .\test.pem /remove BUILTIN\Users
C:\Windows\System32\OpenSSH\sftp.exe -vi .\test.pem -P 2222 user@pi.gaulon.org
```

## Network

```
PS C:\Users\user> tnc api.gaulon.org -Port 443
ComputerName     : api.gaulon.org
RemoteAddress    : 13.35.163.2
RemotePort       : 443
InterfaceAlias   : Ethernet
SourceAddress    : 192.168.0.141
TcpTestSucceeded : True
```

```
$cert = "somebase64encodedcert"
$location = "C:\Windows\Temp\Certificate.pem"
$truststore = "Cert:\LocalMachine\Root"
$cert | %{[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))} | Out-File -FilePath $location
Import-Certificate -FilePath $location -CertStoreLocation $truststore
del $location
```

```
PS C:\WINDOWS\system32> (iwr -UseBasicParsing https://api.gaulon.org/checkip).content
```

```
PS C:\Users\someuser> curl.exe -iw '\n%{certs}\n' https://api.gaulon.org/
HTTP/1.1 404 Not Found
Connection: close
Date: Thu, 08 May 2025 02:03:13 GMT
Content-Length: 1164
Content-Type: text/html; charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

```
PS C:\Users\someuser> Invoke-WebRequest -Method POST -UseBasicParsing -Uri https://api.gaulon.org/ -Certificate (Get-PfxCertificate C:\cert.pfx) -Body "{'message':'Test'}" -ContentType application/json -SkipHttpErrorCheck
Enter password: ********************


StatusCode        : 404
StatusDescription : NotFound
Content           :
RawContent        : HTTP/1.1 404 NotFound
                    Server: awselb/2.0
                    Date: Fri, 23 May 2025 08:36:58 GMT
                    Connection: keep-alive
                    Content-Type: text/plain; charset=utf-8
                    Content-Length: 0


Headers           : {[Server, System.String[]], [Date, System.String[]], [Connection, System.String[]], [Content-Type, System.String[]]…}
Images            : {}
InputFields       : {}
Links             : {}
RawContentLength  : 0
RelationLink      : {}
```

```
iwr https://nmap.org/dist/nmap-7.92-win32.zip -OutFile .\nmap.zip
mkdir nmap
Expand-Archive -Path .\nmap.zip -DestinationPath .\nmap
cd nmap
.\nmap.exe -Pn --traceroute -p 443 pi.gaulon.org
Starting Nmap 7.92 ( https://nmap.org ) at 2025-03-07 04:48 Romance Standard Time
Nmap scan report for pi.gaulon.org (1.2.3.4)
Host is up (1.2s latency).
PORT    STATE SERVICE
443/tcp open  https
TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   1.00 ms   192.168.1.5
[...]
20  243.00 ms 1.2.3.4
Nmap done: 1 IP address (1 host up) scanned in 11.82 seconds
```

### IPSec client

```
PS C:\WINDOWS\system32> Get-VpnConnection -Name "SomeVPN" | Select-Object -Property *
EapConfigXmlStream             : #document
VpnConfigurationXml            : #document
IPSecCustomPolicy              :
MachineCertificateIssuerFilter :
MachineCertificateEKUFilter    :
ConnectionStatus               : Connected
DnsSuffix                      :
Guid                           : {94F26FEA-AB4E-4B79-B78E-FFAF6D11D722}
IdleDisconnectSeconds          : 0
IsAutoTriggerEnabled           : False
Name                           : SomeVPN
ProfileType                    : Inbox
ProvisioningAuthority          :
Proxy                          :
RememberCredential             : True
Routes                         : {}
ServerAddress                  : vpn.gaulon.org
ServerList                     : {}
SplitTunneling                 : False
VpnTrigger                     : VpnConnectionTrigger
AllUserConnection              : False
AuthenticationMethod           : {Eap}
EncryptionLevel                : Optional
L2tpIPsecAuth                  :
NapState                       : NotNapCapable
TunnelType                     : Ikev2
UseWinlogonCredential          : False
PSComputerName                 :
CimClass                       : root/Microsoft/Windows/RemoteAccess/Client:VpnConnection
CimInstanceProperties          : {ConnectionStatus, DnsSuffix, Guid, IdleDisconnectSeconds...}
CimSystemProperties            : Microsoft.Management.Infrastructure.CimSystemProperties
```

```
PS C:\WINDOWS\system32> Get-ChildItem -Path Cert:\* -Recurse | Where-Object {$_.Subject -like "*vpn*"}
   PSParentPath: Microsoft.PowerShell.Security\Certificate::CurrentUser\Root
Thumbprint                                Subject
----------                                -------
1EFE30DBABA2B64591DD505865A7432D94387562  CN=vpn.gaulon.org
   PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\Root
Thumbprint                                Subject
----------                                -------
1EFE30DBABA2B64591DD505865A7432D94387562  CN=vpn.gaulon.org
```

```
PS C:\WINDOWS\system32> Get-EventLog -LogName 'Application' -Source 'RasClient' -Newest 10 | Select-Object -Property Time,Message
Time Message
---- -------
     CoId={E58353A3-B9A8-0000-4A6E-84E5A8B9DB01}: The user POTATO\user has dialed a connection named SomeVPN to the Remote Access Server which has successfully connected. Th...
     CoID={E58353A3-B9A8-0000-4A6E-84E5A8B9DB01}: Connection supports MOBIKE.
     SomeVPN requires attention.
     CoId={E58353A3-B9A8-0000-4A6E-84E5A8B9DB01}: The link to the Remote Access Server has been established by user POTATO\user.
     CoId={E58353A3-B9A8-0000-4A6E-84E5A8B9DB01}: The user POTATO\user has successfully established a link to the Remote Access Server using the following device: ...
     CoId={E58353A3-B9A8-0000-4A6E-84E5A8B9DB01}: The user POTATO\user is trying to establish a link to the Remote Access Server for the connection named SomeVPN using the f...
     CoId={E58353A3-B9A8-0000-4A6E-84E5A8B9DB01}: The user POTATO\user has started dialing a VPN connection using a per-user connection profile named SomeVPN. The connection...
     
PS C:\Users\user\Desktop> logman start gary -ets -p Microsoft-Windows-WFP -o ikev2.etl
The command completed successfully.
PS C:\Users\user\Desktop> logman stop gary -ets
The command completed successfully.

PS C:\Users\user\Desktop> Get-WinEvent -Path .\ikev2.etl -Oldest
   ProviderName:
TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
30/4/2025 4:30:58 PM              0 Information
   ProviderName: Microsoft-Windows-WFP
TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
30/4/2025 4:31:03 PM           1023 Information      IPsec: Negotiation Request Initiated
30/4/2025 4:31:03 PM           1024 Information      IPsec: Send ISAKMP Packet
30/4/2025 4:31:04 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:04 PM           1026 Information      WFP: User Mode Error
30/4/2025 4:31:04 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:04 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:04 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:04 PM           1026 Information      WFP: User Mode Error
30/4/2025 4:31:04 PM           1024 Information      IPsec: Send ISAKMP Packet
30/4/2025 4:31:04 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:04 PM           1026 Information      WFP: User Mode Error
30/4/2025 4:31:04 PM           1024 Information      IPsec: Send ISAKMP Packet
30/4/2025 4:31:04 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:04 PM           1026 Information      WFP: User Mode Error
30/4/2025 4:31:04 PM           1024 Information      IPsec: Send ISAKMP Packet
30/4/2025 4:31:04 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:04 PM           1026 Information      WFP: User Mode Error
30/4/2025 4:31:04 PM           1024 Information      IPsec: Send ISAKMP Packet
30/4/2025 4:31:05 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:05 PM           1028 Information      An IPsec quick mode security association was established.
30/4/2025 4:31:05 PM           1043 Information      IPsec: Main Mode SA Established
30/4/2025 4:31:05 PM           1015 Information      IPsec: Main Mode SA Established
30/4/2025 4:31:11 PM           1013 Information      IPsec: Main Mode SA Terminated
30/4/2025 4:31:11 PM           1027 Information      An IPsec quick mode security association ended.
30/4/2025 4:31:11 PM           1024 Information      IPsec: Send ISAKMP Packet
30/4/2025 4:31:11 PM           1025 Information      IPsec: Receive ISAKMP Packet
30/4/2025 4:31:11 PM           1024 Information      IPsec: Send ISAKMP Packet
30/4/2025 4:31:11 PM           1025 Information      IPsec: Receive ISAKMP Packet
```

```
PS C:\Users\user\Desktop> Get-Service -Name PolicyAgent, IKEEXT
Status   Name               DisplayName
------   ----               -----------
Running  IKEEXT             IKE and AuthIP IPsec Keying Modules
Running  PolicyAgent        IPsec Policy Agent
```

# References
- [Windows Security Internals: A Deep Dive into Windows Authentication, Authorization, and Auditing, by James Forshaw](https://www.amazon.sg/Windows-Security-Internals-Authentication-Authorization/dp/1718501986)
