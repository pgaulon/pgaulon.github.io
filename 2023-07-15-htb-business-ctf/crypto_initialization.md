# [Crypto] Initialization

We are given:

- plaintext messages

```python
[
    'This is some public information that can be read out loud.',
    'No one can crack our encryption algorithm.',
    'HTB{?????????????????????????????????????????????}',
    'Secret information is encrypted with Advanced Encryption Standards.',
]
```

- their ciphertext equivalent

```
76ca21043b5e471169ec20a55297165807ab5b30e588c9c54168b2136fc97d147892b5e39e9b1f1fd39e9f66e7dbbb9d8dffa31b597b53a648676a8d4081a20b
6ccd6818755214527bed6da3008600514bad4d62ac83c1c9417ca3136fc97d146d96b3f8cc910a199ed2fc4093b8dcff
6af60a0c6e5944432af77ea30682076509ae0873e785c79e026b8c1435c566463d8eadc8cecc0c459ecf8e75e7cdfbd88cedd861771932dd224762854889aa03
71c72b057e43145874e522b21f86175304ac1879ffc6cac45077aa1772c377147b93a0ff9eb91a0792929923f19e9f97cee2af1f0d7e53bd0c1a18ea28e3c57fd718b40f5d2c0014a3dbe6a3e5654fe8
```

- the algorithm encrypting the messages into the ciphertext

```python
#!/usr/bin/env python3

import os
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

class AdvancedEncryption:
    def __init__(self, block_size):
        self.KEYS = self.generate_encryption_keys()
        print(self.KEYS)
        self.CTRs = [Counter.new(block_size) for i in range(len(MSG))] # nonce reuse : avoided!
        print(self.CTRs)

    def generate_encryption_keys(self):
        keys = [[b'\x00']*16] * len(MSG)
        for i in range(len(keys)):
            for j in range(len(keys[i])):
                keys[i][j] = os.urandom(1)
        return keys

    def encrypt(self, i, msg):
        key = b''.join(self.KEYS[i])
        ctr = self.CTRs[i]
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(pad(msg.encode(), 16))

def main():
    AE = AdvancedEncryption(128)
    for i in range(len(MSG)):
        ct = AE.encrypt(i, MSG[i])
        print(ct.hex())
    with open('output.txt', 'w') as f:
        for i in range(len(MSG)):
            ct = AE.encrypt(i, MSG[i])
            f.write(ct.hex()+'\n')

if __name__ == '__main__':
    with open('messages.txt') as f:
        MSG = eval(f.read())
    main()
```

This algorithm is using AES [Counter mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)). Reusing the same key and nonce across different message leads to the ability to decrypt messages. This is what we exploit here.

The final exploit takes 2 ciphertexts, and XOR them together. Since the same key is reused it is equivalent to the corresponding 2 plaintext messages XORed. What is left to do is to XOR again with the known plaintext to get the unknown one. This is very similar to [another HTB challenge](https://www.youtube.com/watch?v=Gtfr1dBGzHg).

```python
#!/usr/bin/env python3
import binascii
from pwn import xor

with open('output.txt', 'r') as output:
    ciphertexts = output.read().split("\n")
with open('messages.txt', 'r') as message:
    messages = eval(message.read())

encrypted_flag = binascii.unhexlify(ciphertexts[2].strip())
encrypted_test = binascii.unhexlify(ciphertexts[0].strip())
test = messages[0]
blob = xor(encrypted_test, encrypted_flag)
flag = xor(blob, test[:len(encrypted_flag)])[:len(encrypted_flag)]
print(flag)
```

Which gives

```bash
$ python reverse.py
b'HTB{unpr0t3cted_bl0ckch41n_s3cur1ty_p4r4m3t3rs!!!}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\\`a{(a'
```
