# [Reverse] Wide

WIDE is a challenge presenting one binary, and one database file `db.ex`.

![Files](./img/reverse_wide_1.png).

Running the binary, it shows the encrypted value, that needs a password for decryption:

![Usage](./img/reverse_wide_2.png).

Reading the binary with NSA’s [Ghidra](https://github.com/NationalSecurityAgency/ghidra), in the `menu` function, we notice the password is compared to: `sup3rs3cr3tw1d3`

![Decompile](./img/reverse_wide_3.png)

Using it to get the decrypted value:

![Flag](./img/reverse_wide_4.png)

`HTB{str1ngs_4r3nt_4lw4ys_4sc11}`
