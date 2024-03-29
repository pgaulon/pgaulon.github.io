# [Forensics] Trick or breach

We are also presented with a pcap. Again, running it through tcpdump, we find DNS traffic, with hexadecimal as subdomains:

```bash
$ tcpdump -Ann -r capture.pcap
[...]
21:47:30.355215 IP 147.182.172.189.53 > 192.168.1.10.56333: 37081* 1/0/0 A 147.182.172.189 (100)
E.....@.6..........
.5...l|.............2a120b2000000280100000b0000000000000000000000000050.pumpkincorp.com..............,......
21:47:31.182522 IP 192.168.1.10.55429 > 147.182.172.189.53: 23660 A? 1800005f72656c732f2e72656c73504b010214001400080808.pumpkincorp.com. (84)
E..p......U=...
.......5.\.C\l..........21800005f72656c732f2e72656c73504b010214001400080808.pumpkincorp.com.....
21:47:31.389242 IP 147.182.172.189.53 > 192.168.1.10.55429: 23660* 1/0/0 A 147.182.172.189 (100)
E.....@.6..........
.5...lz.\l..........21800005f72656c732f2e72656c73504b010214001400080808.pumpkincorp.com..............,......
21:47:32.233020 IP 192.168.1.10.55069 > 147.182.172.189.53: 8061 A? 00a52c4755732e8eb934010000a80400001300000000000000.pumpkincorp.com. (84)
E..p......U<...
.......5.\./.}..........200a52c4755732e8eb934010000a80400001300000000000000.pumpkincorp.com.....
21:47:32.403449 IP 147.182.172.189.53 > 192.168.1.10.55069: 8061* 1/0/0 A 147.182.172.189 (100)
E.....@.6..s.......
.5...lb..}..........200a52c4755732e8eb934010000a80400001300000000000000.pumpkincorp.com..............,......
21:47:33.279009 IP 192.168.1.10.62204 > 147.182.172.189.53: 47405 A? 0000000000003b1900005b436f6e74656e745f54797065735d.pumpkincorp.com. (84)
E..p......U;...
.......5.\e..-..........20000000000003b1900005b436f6e74656e745f54797065735d.pumpkincorp.com.....
21:47:33.530276 IP 147.182.172.189.53 > 192.168.1.10.62204: 47405* 1/0/0 A 147.182.172.189 (100)
E....B@.6..........
.5...l...-..........20000000000003b1900005b436f6e74656e745f54797065735d.pumpkincorp.com..............,......
21:47:34.371762 IP 192.168.1.10.52635 > 147.182.172.189.53: 25365 A? 2e786d6c504b0506000000000c000c0036030000b01a000000.pumpkincorp.com. (84)
E..p......U:...
.......5.\.xc...........22e786d6c504b0506000000000c000c0036030000b01a000000.pumpkincorp.com.....
21:47:34.553760 IP 147.182.172.189.53 > 192.168.1.10.52635: 25365* 1/0/0 A 147.182.172.189 (100)
E....2@.6..........
.5...lv$c...........22e786d6c504b0506000000000c000c0036030000b01a000000.pumpkincorp.com..............,......
21:47:35.372678 IP 192.168.1.10.57506 > 147.182.172.189.53: 12854 A? 00.pumpkincorp.com. (36)
E..@......Ui...
.......5.,P.26...........00.pumpkincorp.com.....
21:47:35.577895 IP 147.182.172.189.53 > 192.168.1.10.57506: 12854* 1/0/0 A 147.182.172.189 (52)
E..P..@.5..........
.5...<.626...........00.pumpkincorp.com..............,......
```

Let's filter those hex into a file and convert the hex into bytes with `xxd`.

```bash
$ tcpdump -Ann -r capture.pcap | grep 'A?' | cut -d ' ' -f 8 | cut -d '.' -f 1 > bytes.txt
$ cat bytes.txt | xxd -r -p > file.something
$ file file.something
file.something: Microsoft Excel 2007+
```

We get an Excel file, which is just a zip. After extracting the zip, we can inspect its content:

```bash
$ unzip file.something
$ strings xl/*
[...]
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="28" uniqueCount="22"><si><t>Recipe Assignment</t></si><si><t>In this sheet there are assigned the ingredients of the punken pun secret project.</t></si><si><t>Subject</t></si><si><t>Assignment</t></si><si><t>Status</t></si><si><t>Time</t></si><si><t>Start date</t></si><si><t>Due on</t></si><si><t>Andrew</t></si><si><t>1 Fillet of a fenny snake</t></si><si><t>In progress</t></si><si><t>Nick</t></si><si><t>3 Lizard
s legs</t></si><si><t>Not started</t></si><si><t>3 Bat wings</t></si><si><t>Mike</t></si><si><t>3 Halloween chips</t></si><si><t>Done</t></si><si><t>HTB{M4g1c_c4nn0t_pr3v3nt_d4t4_br34ch}</t></si><si><t>Skipped</t></si><si><t>Team Members</t></si><si><t>Member of the Punkenpun project.</t></si></sst>
[...]
```

We get:

```
HTB{M4g1c_c4nn0t_pr3v3nt_d4t4_br34ch}
```
