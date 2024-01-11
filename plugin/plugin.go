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
	headerWithToken        = "Authheader"
	trash                  = "Trash"
	manual                 = "https://confluence.o3.ru/"
)

var (
	database         = make(map[string]string)
	nameAndIdMapping = make(map[string]string)
	AllowToDo        = []string{
		"/_ping",
		"/images/json",
		"/containers/json?all=1",
		"/containers/json",
	}
	ForbiddenToDo = []string{
		"/commit",
		"/volumes/create",
		"/volumes",
		"/plugins",
	}
)

// CasbinAuthZPlugin is the Casbin Authorization Plugin
type CasbinAuthZPlugin struct {
	// Casbin enforcer
	enforcer *casbin.Enforcer
}

// newPlugin creates a new casbin authorization plugin
func NewPlugin() (*CasbinAuthZPlugin, error) {
	plugin := &CasbinAuthZPlugin{}

	var err error
	plugin.enforcer, err = casbin.NewEnforcer()

	return plugin, err
}

// bypass for admin
func IsItAdmin(keyHash string) bool {
	// if req.RequestHeaders[headerWithToken] != "" {
	// 	keyHash := CalculateHash(req.RequestHeaders[headerWithToken])
	// 	// HIDE THE HASH

	if keyHash == "5eadd4469cb89b077017168e392e7920ba91da5b5f26917224fc6312939d508d" {
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
	// Is it a name of container
	for id := range nameAndIdMapping {
		if containerID == nameAndIdMapping[id] {
			isitNameOfContainer = true
			// redefining containerID
			containerID = id
			break
		}
	}
	// if user sent a containerID with less, than 12 symbols, or less, than 64, but not 12
	if len(containerID) != 64 && len(containerID) != 12 && !isitNameOfContainer {
		IsItShortId := false
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}
		for ID, _ := range database {
			if ID[:len(containerID)] == containerID {
				containerID = ID
				IsItShortId = true
				break
			}
		}
		// we get a trash. Is it bypass. Need to check!
		if !IsItShortId {
			return trash
		}
	}

	return containerID[:12]
}

// Since to containers can be accessed by name, we MUST to know a name of container
// We also solving the problem suspended in the air containers
func CheckDatabaseAndMakeMapa() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	// make "docker ps -a"
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		return err
	}

	// Create map for a quick check of uniqueness
	// Get info from docker daemon and confidently speak
	// this container exist
	isItIdExist := make(map[string]bool)
	for _, container := range containers {
		ID := container.ID[:12]
		// docker daemon usually return /<nameOfContainer>
		// that's why we need to crop a "/""
		name := container.Names[0]
		hasSlash := strings.Contains(name, "/")
		if hasSlash {
			name = strings.TrimLeft(name, "/")
		}
		isItIdExist[ID] = true
		// Put new ID at nameAndIdMapping, don't forget about old containers
		if _, exists := nameAndIdMapping[ID]; !exists {
			nameAndIdMapping[ID] = name
		}
	}

	// Create temporary map for key storage we need to delete from nameAndIdMapping
	keysToDelete := make(map[string]bool)
	for key := range nameAndIdMapping {
		if !isItIdExist[key] {
			keysToDelete[key] = true
		}
	}

	// delete old container also from database
	for oldId := range keysToDelete {
		delete(nameAndIdMapping, oldId)
		_, found := database[oldId]
		if found {
			delete(database, oldId)
		}
	}
	//------------------------------------------
	// DEBUG
	log.Println("NameAndIdMapping:", nameAndIdMapping)
	log.Println("database:", database)
	//------------------------------------------
	return nil
}

// We don't need to save at database a real value of key
// Let's save a hash
func CalculateHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))

	hashKey := hex.EncodeToString(hasher.Sum(nil))
	return hashKey
}

// AuthZReq authorizes the docker client command.
func (plugin *CasbinAuthZPlugin) AuthZReq(req authorization.Request) authorization.Response {
	// Parse request and the request body
	log.Println("------------------------------------------------------------------")
	reqURI, _ := url.QueryUnescape(req.RequestURI)
	reqURL, _ := url.ParseRequestURI(reqURI)

	// if we'll get empty request from docker
	if reqURL == nil {
		return authorization.Response{Allow: true}
	}

	obj := reqURL.String()
	act := req.RequestMethod
	reqBody, _ := url.QueryUnescape(string(req.RequestBody))

	// cropping the version /v1.42/containers/...
	re := regexp.MustCompile(`/v\d+\.\d+/`)
	obj = re.ReplaceAllString(obj, "/")

	//------------------------------------------
	// DEBUG
	log.Println("Headers:", req.RequestHeaders)
	log.Println("Method:", act)
	log.Println("Api:", obj)
	log.Println("Body:", reqBody)
	//------------------------------------------

	for _, j := range AllowToDo {
		if obj == j {
			return authorization.Response{Allow: true}
		}
	}

	for _, j := range ForbiddenToDo {
		if strings.HasPrefix(obj, j) {
			return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin: " + obj}
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
		// Allow create without AuthHeader, because at this step i don't have container ID
		comply, object := containerpolicy.ComplyTheContainerPolicy(reqBody)
		if !comply {
			// if we fall, we get a failed policy
			wordRegex := regexp.MustCompile(`^\w+$`)
			if wordRegex.MatchString(object) {
				msg := fmt.Sprintf("Container Body not comply container policy: %s", object)
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin." + msg}
			} else {
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin." + object}
			}
		}
	}

	if strings.HasPrefix(obj, actionWithContainerAPI) {
		key, found := req.RequestHeaders[headerWithToken]
		if !found {
			instruction := fmt.Sprintf("Access denied by AuthPLugin. Authheader is Empty. Follow instruction - %s", manual)
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

		keyHashFromMapa, found := database[containerID]
		if found {
			if allow := AllowMakeTheAction(keyHashFromMapa, keyHash); allow {
				return authorization.Response{Allow: true}
			} else {
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin. That's not your container"}
			}
		} else {
			log.Println("That's container was created right now:", containerID)
			database[containerID] = keyHash
			return authorization.Response{Allow: true}
		}
	}

	if strings.HasPrefix(obj, execAtContainerAPI) {

		key, found := req.RequestHeaders[headerWithToken]
		if !found {
			instruction := fmt.Sprintf("Access denied by AuthPLugin. Authheader is Empty. Follow instruction - %s", manual)
			return authorization.Response{Allow: false, Msg: instruction}
		}
		keyHash := CalculateHash(key)
		containerID := DefineContainerID(obj)
		if containerID == trash {
			return authorization.Response{Allow: true}
		}

		// can't exec at the container what doesn't exist
		keyFromMapa, found := database[containerID]
		if found {
			if keyFromMapa == keyHash {
				return authorization.Response{Allow: true}
			} else {
				if yes := IsItAdmin(keyHash); yes {
					return authorization.Response{Allow: true}
				}
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin. You can't exec other people's containers"}
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
