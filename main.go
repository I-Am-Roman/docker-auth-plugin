package main

import (
	"flag"
	"log"
	"os"
	"os/user"
	"strconv"

	"github.com/casbin/casbin-authz-plugin/plugin"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/joho/godotenv"
)

const (
	pluginSocket = "/run/docker/plugins/container-authz-plugin.sock"
)

var (
	AdminToken      string
	containerPolicy = flag.String("container policy", "containerPolicy/container_policy.csv", "Specifies the container policy file")
)

func main() {
	flag.Parse()
	pwd, _ := os.Getwd()
	log.Println("Current directory:", pwd)
	log.Println("Container policy:", *containerPolicy)

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}
	AdminToken = os.Getenv("ADMIN_TOKEN")
	plugin.DefineAdminToken(AdminToken)

	authPlugin, err := plugin.NewPlugin()
	if err != nil {
		log.Fatal(err)
	}

	u, _ := user.Lookup("root")
	gid, _ := strconv.Atoi(u.Gid)
	handler := authorization.NewHandler(authPlugin)
	if err := handler.ServeUnix(pluginSocket, gid); err != nil {
		log.Fatal(err)
	}
}
