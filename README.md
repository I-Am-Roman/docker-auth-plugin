# Docker Authorization Plugin Based on Casbin

[![Go Report Card](https://goreportcard.com/badge/github.com)](https://goreportcard.com/report/github.com) [![Build Status](https://travis-ci.org/casbin/casbin.svg?branch=master)](https://travis-ci.org) [![GoDoc](https://godoc.org/github.com/casbin/casbin-authz-plugin?status.svg)](https://godoc.org/github.com)


This plugin controls the access to Docker commands based on authorization policy. Plugin contains:

1. Bypass for admin:
   * Admin can exec at any containers
   * Admin can create any containers
   * For admin working authentication, that means admin's containers will be protected
2. The permission to do:
   * ``/ping``
   * ``/images/json`` docker images 
   * ``/containers/json?all=1`` docker ps -a
   * ``/containers/json`` docker ps
3. The prohibition on execution:
   * ``/plugin`` docker plugin ls, docker plugin create,  docker plugin enable and etc
   * ``/volumes`` docker volumes ls,  docker volumes create and etc
   * ``/commit``
4. The prohibition on creation containers with:
   * ``--privileged`` (Deny if "Privileged" not equal false)
   * ``--cap-add``  (Deny if "CapAdd" not equal null)
   * ``--security-opt`` (Deny if "SecurityOpt" not equal null)
   * ``--pid``  (Deny if "PidMode" not equal ''(empty string))
   * ``--ipc``   (Deny if "IpcMode" not equal '',none,private)
   * ``-v`` Deny if "Binds" not equal:
      * ``/var/run/docker.sock:/var/run/docker.sock``
      * ``/var/run/docker.sock:/var/run/docker.sock:rw``
      * ``/cache,/usr/local/bin/das-cli:/usr/local/bin/das-cli:ro``
   * ``--cgroup-parent`` (Deny if "CgroupParent" not equal ''(empty string))
   * ``--device`` (Deny if "Devices" и "PathInContainer" not equal ''(empty string))
   * ``--network`` (Deny if NetworkMode=host)
5. Authentication when using:
   * ``docker stop``
   * ``docker inspect``
   * ``docker rm``
   * ``docker start``
   * ``docker pause``
   * ``docker unpause``
   * ``docker logs``
   * ``docker exec``
   * ``docker port``
   * ``docker cp``
   * ``docker update``
   * ``docker restart``
   * ``docker kill``
   * and etc command what will requier action with a container
6. Everythilg else will be allow

For example, when you run ``docker commit 4648759b6574`` command, the underlying request is really like:

```
Error response from daemon: authorization denied by plugin container-authz-plugin: Access denied by AuthPLugin: /commit?author=&comment=&container=4648759b6574&repo=&tag=
```

If you'll try to make something (for example ``docker stop epic_buck``) with other's user container, you'll get:
```
Error response from daemon: authorization denied by plugin container-authz-plugin: Access denied by AuthPLugin. That's not your container
```

## Enable the authorization plugin on docker engine

### Step-1: Clone the repo
```bash
$ git clone https://github.com/I-am-Roman/docker-auth-plugin
$ cd docker-auth-plugin
```

### Step-2: Execute the project build (prepare our .socket and .service files too)
```bash
$ make
go build  -o container-authz-plugin .
$ sudo make install
mkdir -p /lib/systemd/system 
install -m 644 systemd/container-authz-plugin.service /lib/systemd/system
install -m 644 systemd/container-authz-plugin.socket /lib/systemd/system
install -m 755 container-authz-plugin /usr/lib/docker
install -m 644 policy/basic_model.conf /usr/lib/docker/policy
install -m 644 policy/basic_policy.csv /usr/lib/docker/policy
install -m 644 containerPolicy/container_policy.csv /usr/lib/docker
```

### Step-3: Define the admin token before the start (optional)
If you want to use bypass for admin, you need to execute:
```bash
$ openssl rand -hex 16
75ea549427986bbea5d2292f7c00f164
$ echo -n "75ea549427986bbea5d2292f7c00f164" | openssl dgst -sha256
7c3aa42f54e7848da56244fbf7844ef3687b6d172cf5a289ad0092da46aeb713
```
And at `/usr/lib/docker`:
```bash
$ nano .env
ADMIN_TOKEN="7c3aa42f54e7848da56244fbf7844ef3687b6d172cf5a289ad0092da46aeb713"
```

### Step-4: Check our service and turn on
```bash
$ systemctl status container-authz-plugin

○ container-authz-plugin.service - Docker RBAC & ABAC Authorization Plugin base>
     Loaded: loaded (/lib/systemd/system/container-authz-plugin.service; disabl>
     Active: inactive (dead)
TriggeredBy: ○ container-authz-plugin.socket

$ systemctl enable container-authz-plugin
$ systemctl start container-authz-plugin
```

### Step-5: Add to the daemon.json "authorization-plugins":["container-authz-plugin"]" 
```bash
$ cd /etc/docker
$ nano daemon.json
{
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
  "max-size": "10m"
 },
  "userns-remap": "default",
  "authorization-plugins":["container-authz-plugin"]
}
```

### Step-6: Restart docker for new settings
```bash
$ systemctl daemon-reload
$ systemctl restart docker
```

### Step-7 Activate the plugin logs:

```bash
$ journalctl -xe -u container-authz-plugin -f
```

### Step-8 Check /.docker/config.json:
You may occur with a next problem if you want to work with a container:

```
$ docker start 4648759b6574
Error response from daemon: authorization denied by plugin container-authz-plugin: Access denied by AuthPLugin. Authheader is Empty. Follow instruction - https://docs.docker.com/engine/reference/commandline/cli/#custom-http-headers
Error: failed to start containers: 4648759b6574
```

That's means in your config you don't have a AuthHeader. It is your secret ID. And 
you MUST HAVE this header if you run, exec, start containers. I've wrote manual for you:
```bash
$ nano setup_dockerAuthToken.sh
```

Copy at the file next:
```bash
docker_dir="$HOME/.docker"
config_file="$docker_dir/config.json"
 
if [ ! -d "$docker_dir" ]; then
    mkdir -p "$docker_dir"
fi
 
if [ ! -f "$config_file" ]; then
    echo '{
  "HttpHeaders": {
    "AuthHeader": "'$(openssl rand -hex 16)'"
  }
}' > "$config_file"
echo "Настройки успешно обновлены в $config_file"
 
else
    if grep -q '"AuthHeader":' "$config_file"; then
        echo "AuthHeader уже существует в $config_file"
    else
    authHeader=$(openssl rand -hex 16)
    jq ". + {\"HttpHeaders\": {\"AuthHeader\": \"$authHeader\"}}" "$config_file" > "$config_file.tmp" && mv "$config_file.tmp" "$config_file"
    echo "Настройки успешно обновлены в $config_file"
 fi
fi
```

Then
```
$ chmod +x setup_dockerAuthToken.sh
$ ./setup_dockerAuthToken.sh
```

My config.json:
```bash
$ cat /.docker/config,json
{
	"auths": {
		"https://index.docker.io/v1/": {
			"auth": "cm9tYXNoa2Fmcm9tZW5nbGFuZDpkY2tyX3BhdF9tc2k3bnNfNkRUdWQ1MzBteU5IeTgydXJlYm8="
		}
	},
	"HttpHeaders": {
		"AuthHeader": "1083f8d29249aecc9c372b210e4135c5"
	},
	"aliases": {
		"builder": "buildx"
	}
```


## Stop and uninstall the plugin as a systemd service

NOTE: Before doing below, remove the authorization-plugin configuration added above and restart the docker daemon.

Removing the authorization plugin on docker

```bash
$ cd /etc/docker
$ nano daemon.json
{
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
  "max-size": "10m"
 },
  "userns-remap": "default"
}

$ systemctl restart docker
```

Stop the plugin service:

```bash
$ systemctl stop container-authz-plugin
$ systemctl disable container-authz-plugin
```

Uninstall the plugin service, where you clone the repo:

```bash
$ make uninstall
```

## Testing

For tests docker plugin you can use https://github.com/I-am-Roman/test-system-dockerAuthPlugin. I have tried to collect the most common cases. However, it is more preferable to use:
```bash
docker-auth-plugin $ go test -count 100 -coverprofile=/tmp/coverage.out ./...
```
I will replenish these files with new cases over time

## Contact

If you have any issues or feature requests, please feel free to contact me at:
- onezhnov@list.ru