package main

import (
	"flag"
	"log"
	"os"
	"os/user"
	"strconv"

	"github.com/casbin/casbin-authz-plugin/plugin"
	"github.com/docker/go-plugins-helpers/authorization"
)

const (
	pluginSocket = "/run/docker/plugins/container-authz-plugin.sock"
)

var (
	authModel       = flag.String("model", "policy/basic_model.conf", "Specifies the model file")
	authPolicy      = flag.String("policy", "policy/basic_policy.csv", "Specifies the policy file")
	containerPolicy = flag.String("container policy", "containerPolicy/container_policy.csv", "Specifies the container policy file")
)

func main() {
	// Parse command line options.
	flag.Parse()
	pwd, _ := os.Getwd()
	log.Println("Current directory:", pwd)
	log.Println("Auth model:", *authModel)
	log.Println("Auth policy:", *authPolicy)
	log.Println("Container policy:", *containerPolicy)

	// Create Casbin authorization plugin
	plugin, err := plugin.NewPlugin(*authModel, *authPolicy)
	if err != nil {
		log.Fatal(err)
	}

	// Start service handler on the local sock
	u, _ := user.Lookup("root")
	gid, _ := strconv.Atoi(u.Gid)
	handler := authorization.NewHandler(plugin)
	if err := handler.ServeUnix(pluginSocket, gid); err != nil {
		log.Fatal(err)
	}
}
