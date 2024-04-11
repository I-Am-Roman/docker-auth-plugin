package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"

	containerpolicy "github.com/casbin/casbin-authz-plugin/containerPolicy"
	"github.com/casbin/casbin/v2"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/authorization"
)

const (
	creationContainerAPI   = "/containers/create"
	actionWithContainerAPI = "/containers/"
	execAtContainerAPI     = "/exec/"
	headerWithToken        = "AuthHeader"
	trash                  = "Trash"
	manual                 = "https://docs.docker.com/engine/reference/commandline/cli/#custom-http-headers"
)

var (
	AdminToken          string
	IDAndHashKeyMapping = make(map[string]string)
	IDAndNameMapping    = make(map[string]string)
	AllowToDo           = []string{
		"/_ping",
		"/images/json",
		"/containers/json?all=1",
		"/containers/json",
	}
	ForbiddenToDo = []string{
		"/commit",
		"/volumes",
		"/plugins",
	}
)

type CasbinAuthZPlugin struct {
	enforcer *casbin.Enforcer
}

func NewPlugin() (*CasbinAuthZPlugin, error) {
	plugin := &CasbinAuthZPlugin{}

	var err error
	plugin.enforcer, err = casbin.NewEnforcer()

	return plugin, err
}

func DefineAdminToken(token string) {
	AdminToken = token
}

func IsItAdmin(keyHash string) bool {
	if keyHash == AdminToken {
		log.Println("Bypass for admin")
		return true
	}
	return false
}

func AllowMakeTheAction(keyHashFromMapa string, keyHash string) bool {
	if keyHashFromMapa == keyHash {
		return true
	} else {
		if yes := IsItAdmin(keyHash); yes {
			return true
		}
		return false
	}
}

func DefineContainerID(obj string) string {
	partsOfApi := strings.Split(obj, "/")
	containerID := partsOfApi[2]
	isitNameOfContainer := false

	for id := range IDAndNameMapping {
		if containerID == IDAndNameMapping[id] {
			isitNameOfContainer = true
			// Redefining containerID
			containerID = id
			break
		}
	}

	// If user sent a containerID with less, than 12 symbols, or less, than 64, but not 12
	if len(containerID) != 64 && len(containerID) != 12 && !isitNameOfContainer {
		IsItShortId := false
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}
		for ID := range IDAndHashKeyMapping {
			if ID[:len(containerID)] == containerID {
				containerID = ID
				IsItShortId = true
				break
			}
		}
		// We get a trash
		if !IsItShortId {
			return trash
		}
	}

	return containerID[:12]
}

// Since containers can be accessed by name,
// We MUST to know the name of container
// We also solve the problem hanging in air containers
func CheckDatabaseAndMakeMapa() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	// similar to the "docker ps -a"
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		return err
	}

	// Create map for a quick check of uniqueness
	// Get info from docker daemon and confidently speak
	// this container exist
	doesThisIDExist := make(map[string]bool)
	for _, container := range containers {
		ID := container.ID[:12]
		name := container.Names[0]

		// Docker Daemon usually return /<nameOfContainer> that's why we need to TrimLeft a "/"
		hasSlash := strings.Contains(name, "/")
		if hasSlash {
			name = strings.TrimLeft(name, "/")
		}

		doesThisIDExist[ID] = true
		if _, exists := IDAndNameMapping[ID]; !exists {
			IDAndNameMapping[ID] = name
		}
	}

	// Create temporary map for key storage we need to delete from IDAndNameMapping
	keysToDelete := make(map[string]bool)
	for key := range IDAndNameMapping {
		if !doesThisIDExist[key] {
			keysToDelete[key] = true
		}
	}

	// Delete old container also from IDAndHashKeyMapping
	for oldId := range keysToDelete {
		delete(IDAndNameMapping, oldId)
		_, found := IDAndHashKeyMapping[oldId]
		if found {
			delete(IDAndHashKeyMapping, oldId)
		}
	}

	return nil
}

func CalculateHash(key string) string {
	hasher := sha256.New()

	_, err := hasher.Write([]byte(key))
	if err != nil {
		log.Fatalf("Failed to write to hasher: %v", err)
	}

	// Get the byte representation of the hash and convert it to a string of hexadecimal representation
	hashKey := hex.EncodeToString(hasher.Sum(nil))
	return hashKey
}

// AuthZReq authorizes the docker client command.
func (plugin *CasbinAuthZPlugin) AuthZReq(req authorization.Request) authorization.Response {

	// Parse request and the request body
	reqURI, _ := url.QueryUnescape(req.RequestURI)
	reqURL, _ := url.ParseRequestURI(reqURI)

	// If we'll get empty request from docker
	if reqURL == nil {
		log.Fatal("Get empty request from docker")
		return authorization.Response{Allow: true}
	}

	obj := reqURL.String()
	reqBody, _ := url.QueryUnescape(string(req.RequestBody))

	// Cropping the version /v1.42/containers/...
	re := regexp.MustCompile(`/v\d+\.\d+/`)
	obj = re.ReplaceAllString(obj, "/")

	for _, j := range AllowToDo {
		if obj == j {
			return authorization.Response{Allow: true}
		}
	}

	for _, j := range ForbiddenToDo {
		keyHash := CalculateHash(req.RequestHeaders[headerWithToken])
		if yes := IsItAdmin(keyHash); yes {
			return authorization.Response{Allow: true}
		}
		if strings.HasPrefix(obj, j) {
			return authorization.Response{Allow: false, Msg: "Access denied by AuthPlugin: " + obj}
		}
	}

	updateRegex := regexp.MustCompile(`/containers/[^/]+/update$`)
	if obj == creationContainerAPI || updateRegex.MatchString(obj) {

		if req.RequestHeaders[headerWithToken] != "" {
			keyHash := CalculateHash(req.RequestHeaders[headerWithToken])
			if yes := IsItAdmin(keyHash); yes {
				return authorization.Response{Allow: true}
			}
		}

		// Allow to create without AuthHeader, because we don't have the container ID at this step
		yes, failedPolicy := containerpolicy.ComplyTheContainerPolicy(reqBody)
		if !yes {
			msg := fmt.Sprintf("Container Body does not comply with the container policy: %s", failedPolicy)
			return authorization.Response{Allow: false, Msg: "Access denied by AuthPlugin." + msg}
		}
	}

	if strings.HasPrefix(obj, actionWithContainerAPI) {
		key, found := req.RequestHeaders[headerWithToken]
		if !found {
			instruction := fmt.Sprintf("Access denied by AuthPlugin. AuthHeader is Empty. Follow the instruction - %s", manual)
			return authorization.Response{Allow: false, Msg: instruction}
		}
		keyHash := CalculateHash(key)

		err := CheckDatabaseAndMakeMapa()
		if err != nil {
			errorMsg := fmt.Sprintf("[CheckDatabaseAndMakeMapa] Error occurred: %e", err)
			log.Println(errorMsg)
		}

		containerID := DefineContainerID(obj)
		if containerID == trash {
			return authorization.Response{Allow: true}
		}

		keyHashFromMapa, found := IDAndHashKeyMapping[containerID]
		if found {
			if allow := AllowMakeTheAction(keyHashFromMapa, keyHash); allow {
				return authorization.Response{Allow: true}
			} else {
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPlugin. That's not your container"}
			}
		} else {
			log.Println("That's container was created right now:", containerID)
			IDAndHashKeyMapping[containerID] = keyHash
			return authorization.Response{Allow: true}
		}
	}

	if strings.HasPrefix(obj, execAtContainerAPI) {

		key, found := req.RequestHeaders[headerWithToken]
		if !found {
			instruction := fmt.Sprintf("Access denied by AuthPlugin. Authheader is Empty. Follow instruction - %s", manual)
			return authorization.Response{Allow: false, Msg: instruction}
		}

		keyHash := CalculateHash(key)
		containerID := DefineContainerID(obj)
		if containerID == trash {
			return authorization.Response{Allow: true}
		}

		keyHashFromMapa, found := IDAndHashKeyMapping[containerID]
		if found {
			if allow := AllowMakeTheAction(keyHashFromMapa, keyHash); allow {
				return authorization.Response{Allow: true}
			} else {
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPlugin. You can't exec other people's containers"}
			}
		}
	}

	return authorization.Response{Allow: true}
}

// AuthZRes authorizes the docker client response.
// All responses are allowed by default.
func (plugin *CasbinAuthZPlugin) AuthZRes(req authorization.Request) authorization.Response {
	// Allowed by default.
	return authorization.Response{Allow: true}
}
