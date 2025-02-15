# Hosting a Capture The Flag event

I have participated to few Capture The Flag (CTF) events over the past years. This time I was given the opportunity to create a private one, with the help of [Pierre Vigier](https://pierre-vigier.github.io/). I was in charge of running the platform while Pierre was taking care of designing the challenges. This article collects my notes and automation to get the CTF platform running.

# Platform description

For this setup, we are running 2 EC2 instances on AWS, in the Singapore `ap-southeast-1` region as it is geographically the closest to our event, located in the Philippines.

One of the machines contains a setup running [CTFd](https://docs.ctfd.io/), and the other one contains the different challenges as Docker images.

```bash
export AWS_REGION=ap-southeast-1
export AWS_PROFILE=sandbox
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID: InstanceId, IP: PublicIpAddress, Name: (Tags[?Key==`Name`].Value | [0]), State: State.Name}' --output table

aws ec2 stop-instances --instance-ids i-abcdef i-ghijkl
aws ec2 start-instances --instance-ids i-abcdef i-ghijkl
```

## CTFd machine

 - 8GB disk
 - t3a.small
 - Security Group allowing: 22/tcp from my IP, 80/tcp from 0.0.0.0/0 (Let’sEncrypt), 443/tcp from 0.0.0.0/0

## Challenges machine

 - 20GB disk
 - t3a.small
 - Security Group allowing: 22/tcp from my IP, 80/tcp from 0.0.0.0/0 (Let’sEncrypt), 1337-1345/tcp from 0.0.0.0/0 for the challenges
 - an IAM role that allows to [pull ECR images](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html)

## DNS entries

For this event we assume that the `example.com` DNS zone is used, and no usage EIP to reduce costs. Each boot of the EC2 will get a different public IP. Hence this small set of commands to update DNS records.

```bash
export AWS_PROFILE=dns-account
aws route53 change-resource-record-sets --hosted-zone-id ABCDEF --change-batch '{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"ctf.example.com","Type":"A","TTL":300,"ResourceRecords":[{"Value":"203.0.113.1"}]}}]}'
aws route53 change-resource-record-sets --hosted-zone-id ABCDEF --change-batch '{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"ctf-challenges.example.com","Type":"A","TTL":300,"ResourceRecords":[{"Value":"203.0.113.2"}]}}]}'
```

## Docker build

Each challenge was created from 1 repo, in a separate branch. From each branch, a docker image is built and pushed to an ECR repo, keeping the name mapping between repo branches and docker tags

```bash
$ tree -L2
.
├── frontend
│   ├── in-html
│   └── in-js
├── logical
│   └── challenge
├── path-traversal
│   └── challenge
├── rce
│   └── ping
├── sqli
│   └── challenge
└── xss
    └── challenge
```

```bash
$ aws ecr get-login-password --region ap-southeast-1 | docker login --username AWS --password-stdin 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com
$ docker build -t rce-ping .
$ docker tag rce-ping:latest 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:rce-ping
$ docker push 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:rce-ping
```

# Setup of CTFd

CTFd is relatively simple to install. It just needs:
 - nginx, the most recent version
 - docker
 - certbot for TLS certificates

```bash
sudo hostnamectl set-hostname ctfd
sudo yum module enable nginx:1.24
sudo dnf -y install dnf-plugins-core epel-release
dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git nginx net-tools certbot python3-certbot-nginx emacs-nox
sudo sed -i 's/server_name  _;/server_name  ctf.example.com;/g' /etc/nginx/nginx.conf
sudo systemctl enable --now nginx
sudo systemctl enable --now docker
sudo certbot run -d ctf.example.com --nginx -n --agree-tos -m pierre.gaulon.cyber+ctf@gmail.com
sudo setsebool -P httpd_can_network_connect 1
sudo useradd ctf -G docker
```

The nginx config is also simple: 1 vhost using the Let’sEncrypt certificate created above

```bash
sudo cat cat <<EOF > /etc/nginx/conf.d/ctf.conf
upstream app_servers {
  server 127.0.0.1:8000;
}
EOF

sudo cat <<EOF >  /etc/nginx/default.d/ctf.conf
gzip on;
client_max_body_size 4G;
# Handle Server Sent Events for Notifications
location /events {
  proxy_pass http://app_servers;
  proxy_set_header Connection '';
  proxy_http_version 1.1;
  chunked_transfer_encoding off;
  proxy_buffering off;
  proxy_cache off;
  proxy_redirect off;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Host $server_name;
}
# Proxy connections to the application servers
location / {
  proxy_pass http://app_servers;
  proxy_redirect off;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Host $server_name;
}
EOF

sudo systemctl restart nginx
```

Finally a separate user is used to run CTFd. A new secret key for authentication is used.

```bash
sudo su - ctf
git clone https://github.com/CTFd/CTFd.git
head -c 64 /dev/urandom > CTFd/.ctfd_secret_key
cd CTFd
docker compose up -d ctfd db cache
docker compose logs -f
```

# Setup of Challenges

Challenges follow the same concept:
  - nginx as frontend. We also want to forbid the use of automated tools such as sqlmap, via the user agent header. This is easily bypassed by `--random-agent`, but serving as 1st layer against DOS
  - Let’sEncrypt as certificate manager
  - docker to run each challenges
  - a separate user
  - the AWS cli to authenticate against ECR

The most complex part is to create a mapping for:

```bash
PortInDocker <-> PortExposedFromDocker <-> PortExposedFromNginx
```

The first part is managed through a docker-compose file. The second via the nginx configuration

```bash
sudo hostnamectl set-hostname ctf-challenges
sudo yum module enable nginx:1.24
sudo dnf -y install dnf-plugins-core epel-release
dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git nginx net-tools certbot python3-certbot-nginx emacs-nox unzip policycoreutils-python-utils
sudo sed -i 's/server_name  _;/server_name  ctf-challenges.example.com;/g' /etc/nginx/nginx.conf
sudo systemctl enable --now nginx
sudo systemctl enable --now docker
sudo certbot run -d ctf-challenges.example.com --nginx -n --agree-tos -m pierre.gaulon.cyber+ctf@gmail.com
sudo setsebool -P httpd_can_network_connect 1
sudo useradd ctf -G docker

for port in $(seq 1337 1345) ; do sudo semanage port -a -t http_port_t  -p tcp $port ; done

curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -d /tmp /tmp/awscliv2.zip
sudo /tmp/aws/install

sudo su - ctf
/usr/local/bin/aws ecr get-login-password --region ap-southeast-1 | docker login --username AWS --password-stdin 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com
cat <<EOF > /home/ctf/docker-compose.yml
services:
  logical:
    image: 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:logical
    restart: always
    ports:
      - "8085:8080"
  sqli:
    image: 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:sqli
    restart: always
    ports:
      - "8086:8080"
  in-js:
    image: 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:in-js
    restart: always
    ports:
      - "8087:8080"
  in-html:
    image: 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:in-html
    restart: always
    ports:
      - "8088:8080"
  xss:
    image: 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:xss
    restart: always
    ports:
      - "8080:8080"
  rce-ping:
    image: 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:rce-ping
    restart: always
    ports:
      - "8089:8080"
  path-traversal:
    image: 12345678910.dkr.ecr.ap-southeast-1.amazonaws.com/security/ctf:path-traversal
    restart: always
    ports:
      - "8090:8080"

networks:
    default:
    internal:
        internal: true
EOF

docker compose stop ; docker compose rm -rf ; docker compose pull ; docker compose up -d
sudo cat <<EOF > /etc/nginx/conf.d/ctf.conf
# in-html 1337 8088
server {
    listen 1337 ssl;
    server_name  ctf-challenges.example.com;
    ssl_certificate /etc/letsencrypt/live/ctf-challenges.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ctf-challenges.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

if ($http_user_agent ~* (sqlmap)){
    return 403;
}

    location / {
        proxy_pass http://127.0.0.1:8088;
    }
}

# in-js 1338 8087
server {
    listen 1338 ssl;
    server_name  ctf-challenges.example.com;
    ssl_certificate /etc/letsencrypt/live/ctf-challenges.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ctf-challenges.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

if ($http_user_agent ~* (sqlmap)){
    return 403;
}

    location / {
        proxy_pass http://127.0.0.1:8087;
    }
}

# sqli 1339 8086
server {
    listen 1339 ssl;
    server_name  ctf-challenges.example.com;
    ssl_certificate /etc/letsencrypt/live/ctf-challenges.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ctf-challenges.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

if ($http_user_agent ~* (sqlmap)){
    return 403;
}

    location / {
        proxy_pass http://127.0.0.1:8086;
    }
}

# rce-ping 1340 8089
server {
    listen 1340 ssl;
    server_name  ctf-challenges.example.com;
    ssl_certificate /etc/letsencrypt/live/ctf-challenges.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ctf-challenges.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

if ($http_user_agent ~* (sqlmap)){
    return 403;
}

    location / {
        proxy_pass http://127.0.0.1:8089;
    }
}

# path-traversal 1341 8090
server {
    listen 1341 ssl;
    server_name  ctf-challenges.example.com;
    ssl_certificate /etc/letsencrypt/live/ctf-challenges.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ctf-challenges.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

if ($http_user_agent ~* (sqlmap)){
    return 403;
}

    location / {
        proxy_pass http://127.0.0.1:8090;
    }
}

# logical 1342 8085
server {
    listen 1342 ssl;
    server_name  ctf-challenges.example.com;
    ssl_certificate /etc/letsencrypt/live/ctf-challenges.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ctf-challenges.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

if ($http_user_agent ~* (sqlmap)){
    return 403;
}

    location / {
        proxy_pass http://127.0.0.1:8085;
    }
}

# xss 1343 8080
server {
    listen 1343 ssl;
    server_name  ctf-challenges.example.com;
    ssl_certificate /etc/letsencrypt/live/ctf-challenges.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ctf-challenges.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

if ($http_user_agent ~* (sqlmap)){
    return 403;
}

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}

EOF
```

# Testing

```bash
for port in $(seq 1337 1343) ; do curl -si https://ctf-challenges.example.com:$port 2>&1 | grep 'HTTP/1.1' ; done
```