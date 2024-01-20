# Notes on SQL Server 2016 SP3 installation on Windows 2022 Server Core

The aim is to replicate SQL Server 2016 SP3 from an on premise database to AWS. Since RHEL support for SQL Server is [only available from 2017](https://learn.microsoft.com/en-us/sql/linux/quickstart-install-connect-red-hat?view=sql-server-linux-2017&tabs=rhel8), Windows Server was the go to choice. To reduce attack surface by limiting the number of components, Core was chosen: all the installation and configuration will be done through the CLI. Finally [version 2022](https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-windows-ami-version-history.html) was used to limit the number of upgrades down the road.

To configure the server and not have to use RDP, manage users and their credentials, and a VPN/Bastion, [AWS SSM](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-install-ssm-win.html) is chosen.

AWS RDS for SQL Server was considered, but doesn't fit the replication purpose as some OS settings need to be changed. [AWS RDS Custom](https://aws.amazon.com/blogs/database/migrate-on-premises-sql-server-workloads-to-amazon-rds-custom-for-sql-server-using-distributed-availability-groups/) was also considered, however it is compatible with SQL Server 2019 only.

As documentation on those very specific conditions was scarce, I decided to write some notes about the process.

# Base Image

The tool of choice to create a base Image on AWS (AMI) was Packer. Using Packer [Powershell provisioner](https://developer.hashicorp.com/packer/docs/provisioners/powershell), the Communicator is [WinRM](https://developer.hashicorp.com/packer/docs/communicators): WinRM must be configured.

This is done using the [WinRM bootstrap script](https://developer.hashicorp.com/packer/integrations/hashicorp/amazon/latest/components/builder/ebs#connecting-to-windows-instances-using-winrm) straight out of Packer documentation: it allows to use encrypted transport (HTTPS) and doesn't assume a static password.

The rest of the Packer script is following the same documentation page, using `Windows_Server-2022-English-Core-Base-2023.08.10`.

The Powershell provisioner will:

 - download and install the Eval version of [SQL Server 2016](https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2016) ([direct link](https://download.microsoft.com/download/A/C/6/AC6F2802-4CC4-40B2-B333-395A4291EF29/SQLServer2016-SSEI-Eval.exe)). For this an SA password must be provided: generating it randomly to reset it later on. It avoids the need to manage secrets.
 - upgrade it to [SP3](https://www.microsoft.com/en-US/download/details.aspx?id=103440) ([direct link](https://download.microsoft.com/download/a/7/7/a77b5753-8fe7-4804-bfc5-591d9a626c98/SQLServer2016SP3-KB5003279-x64-ENU.exe))
 - install management tools such as `sqlcmd` and `aws`
 - open ports `1433/tcp` and `5022/tcp` ports via Windows Firewall

```powershell
# Different teams in different timezones: using UTC to agree on time
Set-TimeZone -Id UTC

# Random password for SA user
Add-Type -AssemblyName 'System.Web'
$password = [System.Web.Security.Membership]::GeneratePassword(24, 2)

# Install SQL server
Invoke-WebRequest -Uri "https://download.microsoft.com/download/A/C/6/AC6F2802-4CC4-40B2-B333-395A4291EF29/SQLServer2016-SSEI-Eval.exe" -OutFile C:\\Users\\Administrator\\Downloads\\SQLServer2016-SSEI-Eval.exe
Start-Process -FilePath C:\\Users\\Administrator\\Downloads\\SQLServer2016-SSEI-Eval.exe -ArgumentList "/QUIET","/ACTION=DOWNLOAD","/MEDIAPATH=C:\\Users\\Administrator\\Downloads","/MEDIATYPE=ISO" -Wait
Mount-DiskImage -ImagePath C:\\Users\\Administrator\\Downloads\\SQLServer2016SP2-FullSlipstream-x64-ENU.iso
cd D:\
Start-Process -FilePath D:\\setup.exe -ArgumentList "/QUIETSIMPLE","/ACTION=INSTALL","/FEATURES=SQLENGINE,CONN","/IACCEPTSQLSERVERLICENSETERMS","/INSTANCENAME=MSSQLSERVER","/TCPENABLED=1","/ASSYSADMINACCOUNTS=Administrator","/SECURITYMODE=SQL","/SQLSYSADMINACCOUNTS=Administrator","/UPDATEENABLED=False","/SAPWD=$password" -Wait

# Update from SP2 to SP3
Invoke-WebRequest -Uri "https://download.microsoft.com/download/a/7/7/a77b5753-8fe7-4804-bfc5-591d9a626c98/SQLServer2016SP3-KB5003279-x64-ENU.exe" -OutFile C:\\Users\\Administrator\\Downloads\\SQLServer2016SP3-KB5003279-x64-ENU.exe
cd C:\\Users\\Administrator\\Downloads
Start-Process -FilePath C:\\Users\\Administrator\\Downloads\\SQLServer2016SP3-KB5003279-x64-ENU.exe -ArgumentList "/QS","/INSTANCENAME=MSSQLSERVER","/IACCEPTSQLSERVERLICENSETERMS","/ACTION=PATCH" -Wait

# Install sqlcmd
Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/8/8/C88C2E51-8D23-4301-9F4B-64C8E2F163C5/x64/MsSqlCmdLnUtils.msi" -OutFile C:\\Users\\Administrator\\Downloads\\MsSqlCmdLnUtils.msi
Start-Process -FilePath C:\Windows\System32\msiexec.exe -ArgumentList "/quiet","/i","C:\\Users\\Administrator\\Downloads\\MsSqlCmdLnUtils.msi" -Wait

# Install SqlServer powershell module
Install-PackageProvider -Name NuGet -Force
Install-Module -Name SqlServer -Force

# Install Failover Clustering feature
Dism /online /Enable-Feature /FeatureName:FailoverCluster-PowerShell /All
Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools

# Install AWS CLI
# In 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
Start-Process -FilePath C:\Windows\System32\msiexec.exe -ArgumentList "/qn","/i","https://awscli.amazonaws.com/AWSCLIV2.msi" -Wait

# Port 1433/tcp for SQL Server, and default port 5022/tcp for data mirroring listener
netsh firewall add portopening TCP 1433 "Port 1433"
netsh firewall add portopening TCP 5022 "Port 5022"
```

# Running the Windows server

The server will be hosted on a `t3.small` EC2 instance. Using Terraform to create the networking parts (VPC with private/public subnets, NACL, IGW, NATgw, Security groups, Routing tables), the server is placed in a private subnet of the VPC. It does need outbound traffic towards port `443/tcp` to communicate with AWS SSM, and AWS S3 in our case.

It can be made available to the outside using a Network Load Balancer using 2 TCP listeners for replication (`1433/tcp` + `5022/tcp`). The newly added Security Group feature for NLB should be used to limit who can access this SQL Server. The reason behind TCP listener and not TLS will be discussed later.

# Post Installation using Ansible

The personalisation of the server needs to be done after the server runs. Because of its agentless feature and ability to use SSM connection, Ansible is used.

## Ansible + SSM

Overall configuration of Ansible to leverage AWS SSM:

```bash
$ cat ansible.cfg
# export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
[defaults]
roles_path = roles/galaxy
vars_plugins_enabled = host_group_vars,community.sops.sops
[inventory]
enable_plugins = aws_ec2,ini
[persistent_connection]
command_timeout = 10

$ cat inventory/000_cross_env_vars
---
ansible_connection: aws_ssm
ansible_shell_type: powershell
ansible_aws_ssm_s3_addressing_style: virtual
ansible_aws_ssm_region: us-east-1

$ cat inventory/prod/aws_ec2.yaml
plugin: aws_ec2
regions:
  - us-east-1
boto_profile: someprofile
keyed_groups:
  - prefix: tag
    key: tags
hostnames:
  - instance-id
filters:
    tag:SSMTag: ssmwindows
compose:
  ansible_host: instance-id
cache: yes
cache_plugin: ansible.builtin.jsonfile
cache_connection: ~/.ansible/tmp-prod
cache_timeout: 300

$ cat inventory/prod/group_vars/all/env_specific
---
ansible_aws_ssm_profile: someprofile
ansible_aws_ssm_bucket_name: somebucket-for-ssm-commands

$ cat inventory/prod/static
[tag_Group_sqlservers]
[sqlservers:children]
tag_Group_sqlservers
```

## SOPS
Secrets, especially SQL Server users, are encrypted with SOPS. AWS KMS or GPG keys can be used.

```bash
$ cat .sops.yaml
creation_rules:
  - path_regex: inventory/prod/.*/vault\.sops\.yml$
    kms: arn:aws:kms:eu-west-1:123456789101112:key/9be23a0c-b4eb-4b2b-b821-e1f55bf125be
    aws_profile: someprofile

$ cat inventory/prod/group_vars/sqlservers/main.yml
---
sqlserver_sa_password: "{{ vaulted_sqlserver_sa_password }}"
sqlserver_clustername: prod
sqlserver_clusterip: "10.0.0.254"
sqlserver_listenerip: "10.0.0.253"
sqlserver_dns: "10.0.0.2"

$ sops inventory/prod/group_vars/sqlservers/vault.sops.yml
vaulted_sqlserver_sa_password: thevaluehere
```

## Playbook

Finally the playbook will contain the different tasks to further personalize the server. For instance the replication Listener needs to leverage 2 additional IPs: another secondary ENI was attached to the EC2 with 2 IP addresses.

```bash
---
- name: Setting up SQL Servers
  hosts: sqlservers
  tasks:
    - name: Set static IP only if not using DHCP
      ansible.windows.win_powershell:
        script: |
          [CmdletBinding()]
          param (
          [String]
          $InterfaceIP,
          [String]
          $InterfaceMask,
          [String]
          $InterfaceGW,
          [String]
          $AwsVpcDns
          )
          $wmi = Get-WmiObject win32_networkadapterconfiguration -filter "ipenabled = 'true'"
          if ($wmi.DHCPEnabled) {
            $wmi.EnableStatic("$InterfaceIP","$InterfaceMask") ; $wmi.SetGateways("$InterfaceGW",1) ; $wmi.SetDNSServerSearchOrder("$AwsVpcDns")
            $Ansible.Changed = $true
          }
          else {
            $Ansible.Changed = $false
          }
        parameters:
          InterfaceIP: "{{ ansible_interfaces[0]['ipv4']['address'] }}"
          InterfaceMask: "{{ ansible_interfaces[0]['ipv4']['address'] + '/' + ansible_interfaces[0]['ipv4']['prefix'] | ipaddr('netmask') }}"
          InterfaceGW: "{{ ansible_interfaces[0]['default_gateway'] }}"
          AwsVpcDns: "{{ sqlserver_dns }}"
      tags:
        - static_ip
        - network

    - name: Configure cluster
      ansible.windows.win_powershell:
        script: |
          [CmdletBinding()]
          param (
          [String]
          $clustername,
          [String]
          $staticAddress,
          [String]
          $administrativeAccessPoint
          )
          New-Cluster -Name "$clustername" -StaticAddress "$staticAddress" -AdministrativeAccessPoint "$administrativeAccessPoint"
        parameters:
          clustername: "{{ sqlserver_clustername }}"
          staticAddress: "{{ sqlserver_clusterip }}"
          administrativeAccessPoint: "Dns"
      tags:
        - cluster
        - sqlserver

    - name: Set SA user password
      become: yes
      become_user: Administrator
      become_method: runas
      register: command_result
      no_log: true
      failed_when: "'\"error\":[]' not in command_result.module_stdout or 'Failed' in command_result.module_stdout"
      changed_when: "'\"changed\":true' in command_result.module_stdout"
      ansible.windows.win_powershell:
        script: .\\SQLCMD.EXE -Q "ALTER LOGIN [sa] WITH PASSWORD=N'{{ sqlserver_sa_password }}'"
        chdir: "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\130\\Tools\\Binn"
      tags:
        - sa_password
        - sqlserver
```

The playbook can be run with:
```bash
$ ansible-playbook -vi inventory/prod sqlservers.yml
```

## TLS

In SQL Server, Transport Layer Security (TLS) is [wrapped in the Tabular Data Stream (TDS) protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/5d627db5-467d-4024-9aa8-da067f419096). That is why it is not possible to offload TLS to a Network Load Balancer. TDS needs to send a [prelogin](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868) packet that is unencrypted. This TDS prelogin packet will contain the TLS handshake payload. The NLB listener will not understand this packet and the TLS session will timeout. Instead, the NLB needs to forward only TCP traffic. And SQL Server will listen to TDS connection that will take charge to negociate TLS as part of the TDS protocol.

In order to enable TLS only 1 setting needs to be changed:

```powershell
> New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib" -Name ForceEncryption -Value 1 -PropertyType DWORD -Force
> Get-Service -Name MSSQLSERVER,SQLSERVERAGENT | Restart-Service -Force
```

This will enable TLS with a self signed certificate generated by SQL Server with the Common Name `SSL_Self_Signed_Fallback`. The TLS versions are dictated by the Windows settings.

If you want to change this certificate, either generate another one, or preferably import a commercial one. The Personal Certificate store `Cert:\LocalMachine\My` is used. Generating a self signed one, with Common Name `$env:COMPUTERNAME`:

```powershell
# Valid 10y for example
$validityMonths = 120
$cert = Get-ChildItem Cert:\LocalMachine\My | ft $env:COMPUTERNAME
if ($cert -eq $null) {
    New-SelfSignedCertificate -Type SSLServerAuthentication -Subject "CN=$env:COMPUTERNAME" -DnsName ("{0}" -f [System.Net.Dns]::GetHostByName($env:computerName).HostName),'localhost' -KeyAlgorithm "RSA" -KeyLength 2048 -HashAlgorithm "SHA256" -TextExtension "2.5.29.37={text}1.3.6.1.5.5.7.3.1" -NotAfter (Get-Date).AddMonths($validityMonths) -KeySpec KeyExchange -Provider "Microsoft RSA SChannel Cryptographic Provider" -CertStoreLocation "cert:\LocalMachine\My"
}
else {
    echo "Certificate for $env:COMPUTERNAME already present"
}
```

SQL Server will need to be told which certificate to use by giving it the certificate Thumbprint (sha1):

```powershell
> $cert = Get-ChildItem Cert:\LocalMachine\My | Where Subject -eq "CN=$env:COMPUTERNAME"
> New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib" -Name Certificate -Value $cert.Thumbprint -PropertyType String -Force
```

Before restarting SQL Server, its service user needs to be allowed to read that certificate file, otherwise the service start will fail with the following error:

```cmd
Unable to load user-specified certificate [Cert Hash(sha1) "5B215BF69D84FC2D68EAB1576F57B2BBE55B98E3"]. The server will not accept a connection. You should verify that the certificate is correctly installed. See "Configuring Certificate for Use by SSL" in Books Online.
TDSSNIClient initialization failed with error 0x80092004, status code 0x80. Reason: Unable to initialize SSL support. Cannot find object or property.
```

To allow it, assuming the Common Name is `$env:COMPUTERNAME`:

```powershell
$certificate = Get-ChildItem Cert:\LocalMachine\My | Where Subject -eq "CN=$env:COMPUTERNAME"
$rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
$fileName = $rsaCert.key.UniqueName
$path = "$env:ALLUSERSPROFILE\Microsoft\crypto\rsa\machinekeys\$fileName"
$permissions = Get-Acl -Path $path
if (-Not $permissions.AccessToString.Contains("NT SERVICE\MSSQLSERVER Allow  Read")) {
  $access_rule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT Service\MSSQLSERVER", 'Read', 'None', 'None', 'Allow')
  $permissions.AddAccessRule($access_rule)
  Set-Acl -Path $path -AclObject $permissions
}
else {
  Write-Host "MSSQL already has read permission on cert $certificate.Thumbprint"
}

# Finally SQL Server can be restarted for the changes to take effect
Get-Service -Name MSSQLSERVER,SQLSERVERAGENT | Restart-Service -Force
```

Validating that TLS is in used from TSQL:

```TSQL
1> SELECT session_id, connect_time, net_transport, encrypt_option, auth_scheme, client_net_address FROM sys.dm_exec_connections
1> GO
```

The `encrypt_option` should be seen as `TRUE`.

If you want to remove TLS:

```powershell
> New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib" -Name ForceEncryption -Value 0 -PropertyType DWORD -Force
> New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib" -Name Certificate -Value "" -PropertyType String -Force
> Get-Service -Name MSSQLSERVER,SQLSERVERAGENT | Restart-Service -Force
```

## Instant File Initialization

To enable [this feature](https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-instant-file-initialization?view=sql-server-2016#enable-instant-file-initialization) (after checking the security implications), the SQL Server service user needs to have the permission `SeManageVolumePrivilege` granted.

```powershell
# Check which user is running MSSQL
> gwmi win32_service | where {$_.DisplayName -match “SQL”} | select name, startname

name           startname
----           ---------
MSSQLSERVER    NT Service\MSSQLSERVER # that's the one
SQLBrowser     NT AUTHORITY\LOCALSERVICE
SQLSERVERAGENT NT Service\SQLSERVERAGENT
SQLTELEMETRY   NT Service\SQLTELEMETRY
SQLWriter      LocalSystem

# Allow SQLServer user SeManageVolumePrivilege
> $sqlaccount = "NT Service\MSSQLSERVER"
> secedit /export /cfg C:\Users\Administrator\Downloads\secexport.txt /areas USER_RIGHTS
> $line = Get-Content C:\Users\Administrator\Downloads\secexport.txt | Select-String 'SeManageVolumePrivilege'
> (Get-Content C:\Users\Administrator\Downloads\secexport.txt).Replace($line,"$line,$sqlaccount") | Out-File C:\Users\Administrator\Downloads\secimport.txt
> secedit /configure /db secedit.sdb /cfg C:\Users\Administrator\Downloads\secimport.txt /overwrite /areas USER_RIGHTS /quiet

# Restart service
> Get-Service -Name MSSQLSERVER,SQLSERVERAGENT | Restart-Service -Force
```

To verify that it is in place

```TSQL
1> select instant_file_initialization_enabled,service_account from sys.dm_server_services where servicename like 'SQL Server%';
2> go
instant_file_initialization_enabled service_account
----------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Y                                   NT Service\MSSQLSERVER
N                                   NT Service\SQLSERVERAGENT

(2 rows affected)
```

`instant_file_initialization_enabled` is enabled for user `NT Service\MSSQLSERVER`

# Miscellaneous

## Using AWS NTP server

```cmd
> w32tm /config /manualpeerlist:169.254.169.123 /syncfromflags:manual /update
```

## Locked out

If you ever get locked out of SQL Server, you can configure it to run in Single User mode, and reset the SA user password. Here is the one liner for it:

```cmd
> net stop mssqlserver && net start mssqlserver /m && sqlcmd -Q "ALTER LOGIN admin WITH PASSWORD = 'newpassword'"
```

## License upgrade

Once the setup is validated, you will want to use a paid license. This is done either by using the Product ID (`/PID=value`) during the installation, or add it post install:

```cmd
> Setup.exe /q /ACTION=EditionUpgrade /INSTANCENAME=MSSQLSERVER /PID=value /IACCEPTSQLSERVERLICENSETERMS /SkipRules=Engine_SqlEngineHealthCheck
```

To check how much longer you have your evaluation for

```TSQL
1> SELECT create_date AS 'SQL Server Install Date', DATEADD(DD, 180, create_date) AS 'SQL Server Expiration Date' FROM sys.server_principals WHERE name = 'NT AUTHORITY\SYSTEM'
2> go
SQL Server Install Date SQL Server Expiration Date
----------------------- --------------------------
2023-08-27 03:21:50.020    2024-02-23 03:21:50.020

(1 rows affected)
```

## Check if TCP is enabled and if dynamic/static port is used

To enable [static](https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/connect/static-or-dynamic-port-config#option-2-use-powershell) port, use the property `TcpPort`.

```powershell
PS C:\Windows\system32> Get-ItemProperty  -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.*\MSSQLServer\SuperSocketNetLib\Tcp" | Select-Object -
Property Enabled, KeepAlive, ListenOnAllIps,@{label='ServerInstance';expression={$_.PSPath.Substring(74)}} |Format-Table -AutoSize

Enabled KeepAlive ListenOnAllIPs ServerInstance
------- --------- -------------- --------------
      1     30000              1 Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp

PS C:\Windows\system32> Get-ItemProperty  -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.*\MSSQLServer\SuperSocketNetLib\Tcp\IP*\" | Select-Obj
ect -Property TcpDynamicPorts,TcpPort,DisplayName, @{label='ServerInstance_and_IP';expression={$_.PSPath.Substring(74)}}, IpAddress |Format-Table -AutoSize

TcpDynamicPorts TcpPort DisplayName         ServerInstance_and_IP                                                                IpAddress
--------------- ------- -----------         ---------------------                                                                ---------
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP1   fe80::e51c:8701:b5d1:65f8%9
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP2   10.34.3.55
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP3   10.34.3.253
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP4   10.34.3.254
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP5   fe80::c754:6e30:d750:b6e0%6
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP6   169.254.1.152
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP7   169.254.192.110
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP8   ::1
0                       Specific IP Address Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IP9   127.0.0.1
57064                   Any IP Address      Microsoft SQL Server\MSSQL13.MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp\IPAll
```

## Check if TLS is in use, and its allowed versions

```shell
$ nmap -Pn -v --script=ssl-enum-ciphers --script=ssl-cert -p 1433 sqlserver.example.com
```

## Listing AWS S3 IPs

For firewall use:

```shell
$ curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq '.prefixes[] | select(.region == "eu-west-1") | select(.service == "S3") | .ip_prefix'
```

## Allowing anyone to read a file

```powershell
PS C:\Windows\Temp> icacls .\backup* /inheritance:r /grant:r Everyone:R
processed file: .\backup1.bak
processed file: .\backup2.bak
processed file: .\backup3.bak
processed file: .\backup4.bak
processed file: .\backup5.bak
processed file: .\backup6.bak
processed file: .\backup7.bak
processed file: .\backup8.bak
Successfully processed 8 files; Failed processing 0 files
```

## Replication authentication

In this case we wanted to avoid having to create a VPN to connect to the main Active Directory and have the replication authentication follow AD users. Instead Certificate authentication was used. This means that the main SQL Server and the Replica SQL Server both generate certificates with their private keys, and exchange the public parts.

The exchange process can be simplified with few lines:

```bash
# exporting a certificate to DER format
$ sqlcmd -N -C -S tcp:replica.example.com,1433 -U sa -d master -Q "SELECT CERTENCODED(C.certificate_id) FROM sys.certificates C WHERE C.name = 'Test_cert';" | xxd -r -p > test.cer

# importing the DER format to a new SQL Certificate via BINARY
$ export cert_bin=$(xxd -p < test.cer | tr -d "\n")
$ sqlcmd -N -C -S tcp:main.example.com,1433 -U sa -d master -Q "CREATE CERTIFICATE Test_cert AUTHORIZATION Test_User FROM BINARY = 0x$cert_bin;"

# same process can be done with a certificate and its private key, to restore an encrypted backup for instance
$ export cert_bin=$(xxd -p < encryption_cert.der | tr -d "\n")
$ export key_bin=$(xxd -p < encryption_cert_private_key.der | tr -d "\n")
$ cat pass.sh
export pass='privatekeypasswordhere'
$ source pass.sh
$ sqlcmd -N -C -S tcp:main.example.com,1433 -U sa -d master -Q "create certificate encryption_certificate FROM BINARY = 0x$cert_bin with private key ( binary = 0x$key_bin , decryption by password = '$pass' )"
```
