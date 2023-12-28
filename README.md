# Docker Authorization Plugin Based on Casbin

[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/casbin-authz-plugin)](https://goreportcard.com/report/github.com/casbin/casbin-authz-plugin) [![Build Status](https://travis-ci.org/casbin/casbin.svg?branch=master)](https://travis-ci.org/casbin/casbin) [![GoDoc](https://godoc.org/github.com/casbin/casbin-authz-plugin?status.svg)](https://godoc.org/github.com/casbin/casbin-authz-plugin)

This plugin controls the access to Docker commands based on authorization policy. Plugin contains:

1. Bypass for admin 
2. Permission to do:
   * ``/ping``
   * ``/images/json`` docker images 
   * ``/containers/json?all=1`` docker ps -a
   * ``/containers/json`` docker ps
3. The prohibition on execution:
   * ``/plugin`` docker plugin ls, docker plugin create,  docker plugin enable and etc
   * ``/volumes`` docker volumes ls,  docker volumes create and etc
   * ``/commit``
4. The prohibition on creation containers with:
   * ``--privileged ("Privileged" not equal false)``
   * ``--cap-add  ("CapAdd" not equal null)``
   * ``--security-opt ("SecurityOpt" not equal null)``
   * ``--pid  ("PidMode" not equal ''(empty string))``
   * ``--ipc   ("IpcMode" not equal '',none,private)``
   * ``-v ("Binds" not equal:``
      * ``/var/run/docker.sock:/var/run/docker.sock``
      * ``/var/run/docker.sock:/var/run/docker.sock:rw``
      * ``/cache,/usr/local/bin/das-cli:/usr/local/bin/das-cli:ro``
   * ``--cgroup-parent ("CgroupParent" not equal ''(empty string))``
   * ``--device ("Devices" и "PathInContainer" not equal ''(empty string)``
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


## Enable the authorization plugin on docker engine

### Step-1: Clone the repo
```bash
$ git clone https://github.com/I-am-Roman/docker-auth-plugin
$ cd docker-auth-plugin
```

### Step-2: Exrcute the project build (prepare our .socket and .service files too)
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

### Step-3: Check our service and turn on
```bash
$ systemctl status container-authz-plugin

○ container-authz-plugin.service - Docker RBAC & ABAC Authorization Plugin base>
     Loaded: loaded (/lib/systemd/system/container-authz-plugin.service; disabl>
     Active: inactive (dead)
TriggeredBy: ○ container-authz-plugin.socket

$ systemctl enable container-authz-plugin
$ systemctl start container-authz-plugin
```

### Step-4: Add to the daemon.json "authorization-plugins":["container-authz-plugin"]" 
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

### Step-5: Restart docker for new settings
```bash
$ systemctl daemon-reload
$ systemctl restart docker
```

### Step-6 Activate the plugin logs:

```bash
$ journalctl -xe -u container-authz-plugin -f
```

### Step-6 Check /.docker/config.json:
You may occur with a next problem if you want to work with a container:

```
$ docker start 4648759b6574
Error response from daemon: authorization denied by plugin container-authz-plugin: Access denied by AuthPLugin. Authheader is Empty. Follow instruction - https://confluence.o3.ru/
Error: failed to start containers: 4648759b6574
```

That's means in your config you don't have a AuthHeader. It is your secret ID. And 
you MUST HAVE this header if you run, exec, start containers. I've wrote manual for you:
```bash
$ nano setup_dockerAuthToken.sh
```

Copy at the file next:
```bash
# Путь к директории ~/.docker
docker_dir="$HOME/.docker"
 
# Путь к файлу config.json
config_file="$docker_dir/config.json"
 
# Проверка наличия директории ~/.docker, понятный язык
if [ ! -d "$docker_dir" ]; then
    mkdir -p "$docker_dir"
fi
 
# Проверка наличия файла config2.json
if [ ! -f "$config_file" ]; then
    # Если файла нет, создаем его с нужным содержимым заголовком
    echo '{
  "HttpHeaders": {
    "AuthHeader": "'$(openssl rand -hex 16)'"
  }
}' > "$config_file"
echo "Настройки успешно обновлены в $config_file"
 
else
    # Если файл есть, проверяем наличие "AuthHeader"
    if grep -q '"AuthHeader":' "$config_file"; then
        echo "AuthHeader уже существует в $config_file"
    else
    # Если "AuthHeader" отсутствует, добавляем его в самый конец с помощью jq
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

My congig.json:
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

## Contact

If you have any issues or feature requests, please feel free to contact me at:
- onezhnov@list.ru