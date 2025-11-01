# Introduction

The aim is to provide a single binary to test RDP TLS settings without installing another software. Unfortunately nmap didn't work with this example as it didn't recognise RDP through STARTTLS.

```
.\nmap.exe -Pn -sV --script rdp-enum-encryption,ssl-enum-ciphers -p 3389 127.0.0.1
```

Instead, [sslyze](https://github.com/nabla-c0d3/sslyze) will be used.

# Requirements

This setup starts with a Windows machine that is accessible through [OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell&pivots=windows-11). Powershell is setup as preferred shell.

```
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
```

It also has [Chocolatey](https://chocolatey.org/install#individual) installed, along with [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) and [git](https://git-scm.com/install/windows)
```
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco install git --params "/GitAndUnixToolsOnPath"
setx PATH "%PATH%;C:\Program Files\Git\bin;C:\Program Files\Git\cmd"
choco install psexec
```

[UV](https://docs.astral.sh/uv/guides/install-python/) is also installed, with Python 3.12
```
irm https://astral.sh/uv/install.ps1 | iex
uv python install 3.12
```

# Setup

The sslyze repo is cloned locally, and a virtual env is created for the dependencies and [PyInstaller](https://pyinstaller.org/en/stable/installation.html)
```
git clone https://github.com/nabla-c0d3/sslyze.git
cd sslyze
uv venv --python 3.12
.venv\Scripts\activate
uv pip install -r .\requirements-dev.txt
uv pip install pyinstaller
```

Finally pyinstaller is used to create a single binary. Part of the trial and error, there are some [data files](https://github.com/nabla-c0d3/sslyze/tree/release/sslyze/mozilla_tls_profile) that need to be included in the resulting `.exe` file
```
pyinstaller.exe --onefile .\sslyze\__main__.py --add-data "sslyze\\mozilla_tls_profile\\5.7.json:sslyze\\mozilla_tls_profile"
```

There are other static files (as in non `.py` files) that are needed. From errors, they seem to be fetched from a [local directory](https://github.com/nabla-c0d3/sslyze/blob/release/sslyze/plugins/certificate_info/trust_stores/trust_store_repository.py#L46) called `pem_files` next to the binary. It can be created at runtime.
```
copy .\dist\__main__.exe ..\..\Desktop\sslyze.exe
cd ..\..\Desktop\
mkdir pem_files
.\sslyze.exe --update_trust_stores
.\sslyze.exe 127.0.0.1:3389 --starttls rdp
rmdir .\pem_files\
del sslyze.exe
```

The result looks like this
```
.\sslyze.exe 127.0.0.1:3389 --starttls rdp
 CHECKING CONNECTIVITY TO SERVER(S)
 ----------------------------------
   127.0.0.1:3389            => 127.0.0.1
[...]
 SCANS COMPLETED IN 5.326116 S
 -----------------------------
 COMPLIANCE AGAINST TLS CONFIGURATION
 ------------------------------------
    Checking results against Mozilla's "intermediate" configuration. See https://ssl-config.mozilla.org/ for more details.
    127.0.0.1:3389: FAILED - Not compliant.
        * certificate_path_validation: Certificate path validation failed for CN=potato.
        * tls_versions: TLS versions {'TLSv1', 'TLSv1.1'} are supported, but should be rejected.
        * ciphers: Cipher suites {'TLS_RSA_WITH_AES_256_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'} are supported, but should be rejected.
        * tls_vulnerability_fallback_scsv: Server is vulnerable to TLS downgrade attacks because it does not support the TLS_FALLBACK_SCSV mechanism.
```
