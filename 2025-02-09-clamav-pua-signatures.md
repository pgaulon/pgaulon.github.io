# Clamscan PUA PDF signatures

## Introduction

While reviewing penetration testing reports, I stumbled upon an odd case. The pentester used a generated PDF, using [AcroJS](https://opensource.adobe.com/dc-acrobat-sdk-docs/library/jsapiref/index.html) to run a Javascript through the `app.alert` call. While all the incoming files are scanned using ClamAV with the [Potentially Unwanted Application flag](https://docs.clamav.net/faq/faq-pua.html) enabled, somehow this one was not caught.

```bash
$ clamscan -v --detect-pua -a --stdout -d /tmp/test example.pdf
Loading:    16s, ETA:   0s [========================>]    8.72M/8.72M sigs
Compiling:   4s, ETA:   0s [========================>]       41/41 tasks

Scanning example.pdf
example.pdf: OK

----------- SCAN SUMMARY -----------
Known viruses: 8719530
Engine version: 1.4.2
Scanned directories: 0
Scanned files: 1
Infected files: 0
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 20.456 sec (0 m 20 s)
Start Date: 2025:02:09 14:11:43
End Date:   2025:02:09 14:12:03
```

Beyond the [discussion](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#Does-executing-JavaScript-in-a-PDF-file-mean-there_s-an-XSS-vulnerability) whether a PDF running a Javascript is a valid finding or not, the interesting bit is that a PDF that contains a Javascript is not picked up, while PUA detection is on.

## Reviewing ClamAV PUA PDF detection rules

The obvious next step is to compare the PUA PDF signature, downloaded by `freshclam`, and the content of the PDF generated.

Running `freshclam`, we gather the up to date definitions, and extract the signatures packaged in the `daily.cvd` file:
```bash
$ freshclam --datadir=/tmp/test
$ ls /tmp/test
daily.cvd      freshclam.dat  main.cvd

$ sigtool -u /tmp/test/daily.cvd
$ ls
COPYING        daily.crb      daily.ftm      daily.hsb      daily.ign      daily.ldb      daily.mdu      daily.ndb      daily.sfp      main.cvd
daily.cdb      daily.cvd      daily.hdb      daily.hsu      daily.ign2     daily.ldu      daily.msb      daily.ndu      daily.wdb
daily.cfg      daily.fp       daily.hdu      daily.idb      daily.info     daily.mdb      daily.msu      daily.pdb      freshclam.dat
```

Finally we grep for our PUA PDF signature
```bash
$ grep PUA.Pdf *
daily.ldu:PUA.Pdf.Trojan.EmbeddedFile-1;Engine:51-255,Target:10;0&1&(2|3|4);2f46696c746572205b2f{-12}4465636f6465202f{-12}4465636f6465202f{-12}4465636f6465;2F456D62656464656446696C65;2F54797065202F46696C6573706563202F462028{-100}2E70646629;2F54797065202F46696C6573706563202F462028{-100}2E65786529;2F54797065202F46696C6573706563202F462028{-100}2E646c6c29
daily.ldu:PUA.Pdf.Exploit.CVE_2013_0624-4255860-2;Engine:51-255,HandlerType:CL_TYPE_PDF,Target:0;(0|1|2|3);0:474946383961{-1024}255044462d;0:89504e470d0a1a0a{-1024}255044462d;0:ffd8ffe0{-800}faffda000c{-1024}255044462d;0:d0cf11e0{-1024}255044462d
daily.ndu:PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1:0:0:255044462d*6f626a{-2}3c3c{-100}2f4f70656e416374696f6e{-100}2f4a617661536372697074
daily.ndu:PUA.Pdf.Trojan.OpenActionObjectwithJS-1:0:0:255044462d*6f626a{-2}3c3c{-100}2f4f70656e416374696f6e{-100}2f4a53
daily.ndu:PUA.Pdf.Trojan.CVE_2013_0622-1:0:*:255044462d*6f626a{-4}3c3c{-100}2e6f70656e446f6328{-25}63506174683a{-10}5c5c5c5c
```

The 2 interesting rules are in the `daily.ndu` file:
 - PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1
 - PUA.Pdf.Trojan.OpenActionObjectwithJS-1

Let's show their content in a friendlier way

```bash
$ cat extract/daily.ndu | sigtool --decode-sigs | grep -aA 4 'PUA.Pdf.Trojan.OpenActionObject'
VIRUS NAME: PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1
TARGET TYPE: ANY FILE
OFFSET: 0
DECODED SIGNATURE:
%PDF-{WILDCARD_ANY_STRING}obj{WILDCARD_ANY_STRING(LENGTH<=2)}<<{WILDCARD_ANY_STRING(LENGTH<=100)}/OpenAction{WILDCARD_ANY_STRING(LENGTH<=100)}/JavaScript
VIRUS NAME: PUA.Pdf.Trojan.OpenActionObjectwithJS-1
TARGET TYPE: ANY FILE
OFFSET: 0
DECODED SIGNATURE:
%PDF-{WILDCARD_ANY_STRING}obj{WILDCARD_ANY_STRING(LENGTH<=2)}<<{WILDCARD_ANY_STRING(LENGTH<=100)}/OpenAction{WILDCARD_ANY_STRING(LENGTH<=100)}/JS
```

Right, the main pattern is to detect the PDF magic bytes `%PDF-`, with any version number, followed by an `obj`. After that, the pattern watches for `/OpenAction` and `/JavaScript` (or `/JS`). The important bit is the `{WILDCARD_ANY_STRING(LENGTH<=100)}` between the 2 of them. That means if there's more that 100 characters in the PDF file between the `/OpenAction` and the `/JavaScript`, the file is accepted as clean of PUA.

What if we generate a file that is still parsed by PDF readers, but has `/OpenAction` and `/JavaScript` (again, or `/JS`) further away than 100 characters?

## Bypassing the ClamAV PUA PDF rules

In order to reproduce the example, we need:
 - a valid PDF
 - using `/OpenAction` and more that 100 characters before the 1st occurence of `/JavaScript`

Using [pypdf](https://pypdf.readthedocs.io/en/stable/modules/PdfWriter.html), the following program generates such file

```python
$ cat example.py
from pypdf import PdfWriter
writer = PdfWriter()
writer.pdf_header = '%PDF-1.5'
writer.metadata = {
    '/OpenAction': '5 0 R',
    '/Producer': 'A'*100
}
writer.add_blank_page(width=1, height=1)
writer.add_js('app.alert("test");')
with open("example.pdf", "wb") as fp:
    writer.write(fp)
```

The result is the following
```bash
$ cat example.pdf
%PDF-1.5
%����
1 0 obj
<<
/OpenAction (5 0 R)
/Producer (AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
>>
endobj
2 0 obj
<<
/Type /Pages
/Count 1
/Kids [ 4 0 R ]
>>
endobj
3 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [ (b0d741f5\0556913\05540fa\05594a3\055ae0e45c1be53) 5 0 R ]
>>
>>
>>
endobj
4 0 obj
<<
/Type /Page
/Resources <<
>>
/MediaBox [ 0.0 0.0 1 1 ]
/Parent 2 0 R
>>
endobj
5 0 obj
<<
/Type /Action
/S /JavaScript
/JS (app\056alert\050\042test\042\051\073)
>>
endobj
xref
0 6
0000000000 65535 f
0000000015 00000 n
0000000169 00000 n
0000000228 00000 n
0000000376 00000 n
0000000466 00000 n
trailer
<<
/Size 6
/Root 3 0 R
/Info 1 0 R
>>
startxref
559
%%EOF
```

Testing with the default rules, indeed this is not picked up, while opening the file with any browser does show the Javascript alert box.

```bash
$ clamscan -v --detect-pua -a --stdout -d /tmp/test example.pdf
Loading:    16s, ETA:   0s [========================>]    8.72M/8.72M sigs
Compiling:   4s, ETA:   0s [========================>]       41/41 tasks

Scanning example.pdf
example.pdf: OK

----------- SCAN SUMMARY -----------
Known viruses: 8719530
Engine version: 1.4.2
Scanned directories: 0
Scanned files: 1
Infected files: 0
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 20.456 sec (0 m 20 s)
Start Date: 2025:02:09 14:11:43
End Date:   2025:02:09 14:12:03
```

## Creating my own PUA PDF rule

What if we still want to alert on such PDF, whether the finding is legitimate or not? We would need to come up with a rule, that allows more that 100 characters between `/OpenAction` and `/JavaScript`.
Taking back the rules given by ClamAV `daily.ndu`, extracted from `daily.nvd` the change is quite simple:

```bash
$ cat rules.ndu
PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1:0:0:255044462d*6f626a{-2}3c3c{-100}2f4f70656e416374696f6e*2f4a617661536372697074
```

We replace the second occurence of `{-100}` to a wildcard `*`. Explaining in ClamAV own words

```bash
$ cat rules.ndu | sigtool --decode-sigs
VIRUS NAME: PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1
TARGET TYPE: ANY FILE
OFFSET: 0
DECODED SIGNATURE:
%PDF-{WILDCARD_ANY_STRING}obj{WILDCARD_ANY_STRING(LENGTH<=2)}<<{WILDCARD_ANY_STRING(LENGTH<=100)}/OpenAction{WILDCARD_ANY_STRING}/JavaScript
```

Let's try to detect our sample

```bash
$ cp rules.ndu /tmp/test/
$ clamscan -v --detect-pua -a --stdout -d /tmp/test example.pdf
Loading:    17s, ETA:   0s [========================>]    8.72M/8.72M sigs
Compiling:   4s, ETA:   0s [========================>]       41/41 tasks

Scanning example.pdf
example.pdf: PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1.UNOFFICIAL FOUND
example.pdf!(1): PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1.UNOFFICIAL FOUND

----------- SCAN SUMMARY -----------
Known viruses: 8719531
Engine version: 1.4.2
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 20.967 sec (0 m 20 s)
Start Date: 2025:02:09 14:21:35
End Date:   2025:02:09 14:21:56
```

There we go, we can now detect occurences of Javascript within PDF, no matter the distance from `/OpenAction`
