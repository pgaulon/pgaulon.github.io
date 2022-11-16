# [Reverse] Cult meeting

We are given a binary, that is asking for a password. Running `strings` on the binary gives us the password that needs to be used.

```
$ strings meeting
[...]
[3mYou knock on the door and a panel slides back
[3m A hooded figure looks out at you
"What is the password for this week's meeting?"
sup3r_s3cr3t_p455w0rd_f0r_u!
[3mThe panel slides closed and the lock clicks
|      | "Welcome inside..."
/bin/sh
   \/
 \| "That's not our password - call the guards!"
;*3$"
```

Using the password from the binary leads us to a shell (`/bin/sh`), which we can use to `cat flag.txt`
