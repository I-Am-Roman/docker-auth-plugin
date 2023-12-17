package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/authorization"
)

var database = make(map[string]string)
var nameAndIdMapping = make(map[string]string)

// CasbinAuthZPlugin is the Casbin Authorization Plugin
type CasbinAuthZPlugin struct {
	// Casbin enforcer
	enforcer *casbin.Enforcer
}

// newPlugin creates a new casbin authorization plugin
func NewPlugin(casbinModel string, casbinPolicy string) (*CasbinAuthZPlugin, error) {
	plugin := &CasbinAuthZPlugin{}

	var err error
	plugin.enforcer, err = casbin.NewEnforcer(casbinModel, casbinPolicy)

	return plugin, err
}

func CheckDatabaseAndMakeMapa() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		return err
	}

	// Create map for a quick check of uniqueness
	isItIdExist := make(map[string]bool)
	for _, container := range containers {
		ID := container.ID[:12]
		// docker daemon usually return /<nameOfContainer>
		name := container.Names[0]
		hasSlash := strings.Contains(name, "/")
		if hasSlash {
			name = strings.TrimLeft(name, "/")
		}
		isItIdExist[ID] = true
		if _, exists := nameAndIdMapping[ID]; !exists {
			nameAndIdMapping[ID] = name
		}
	}

	// Create temporary map for key storage we need tp delete
	keysToDelete := make(map[string]bool)
	for key := range nameAndIdMapping {
		if !isItIdExist[key] {
			keysToDelete[key] = true
		}
	}

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

func calculateHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))

	hashKey := hex.EncodeToString(hasher.Sum(nil))
	return hashKey
}

func complyTheContainerPolicy(body string) (bool, string) {
	file, err := os.Open("policy/container policy/container_policy.csv")
	if err != nil {
		e := fmt.Sprintf("Ошибка при открытии файла:%e", err)
		return false, e
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		e := fmt.Sprintf("Ошибка при чтении CSV:%e", err)
		return false, e
	}

	for _, row := range records {
		nameOfKey := row[0]
		value := row[1]
		typeOfData := row[2]

		var searcher string
		var mustNotContain = false

		switch typeOfData {
		case "slice":
			searcher = fmt.Sprintf(`"%s":\["([^"]+(?:","[^"]+)*)"\]`, nameOfKey)
		case "string":
			searcher = fmt.Sprintf(`"%s":"([^"]+)"`, nameOfKey)
		case "bool":
			searcher = fmt.Sprintf(`"%s":([^",]+)`, nameOfKey)
		case "cmd":
			searcher = fmt.Sprintf(`"%s":\["([^"]+(?:","[^"]+)*)"\]`, nameOfKey)
			mustNotContain = true
		}
		re := regexp.MustCompile(searcher)
		match := re.FindStringSubmatch(body)
		if match != nil {
			if !mustNotContain {
				if match[1] != value {
					return false, nameOfKey
				}
			} else {
				data := "\"" + match[1] + "\""
				if strings.Contains(data, value) {
					return false, nameOfKey
				} else {
					continue
				}
			}
		}
	}
	return true, ""
}

// AuthZReq authorizes the docker client command.
// The command is allowed only if it matches a Casbin policy rule.
// Otherwise, the request is denied!
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

	re := regexp.MustCompile(`/v\d+\.\d+/`)
	obj = re.ReplaceAllString(obj, "/")

	//------------------------------------------
	// DEBUG
	log.Println("Headers:", req.RequestHeaders)
	log.Println("Method:", act)
	log.Println("Api:", obj)
	log.Println("Body:", reqBody)
	//------------------------------------------

	updateRegex := regexp.MustCompile(`/containers/[^/]+/update$`)
	if obj == "/containers/create" || updateRegex.MatchString(obj) {
		comply, object := complyTheContainerPolicy(reqBody)
		if !comply {
			wordRegex := regexp.MustCompile(`^\w+$`)
			if wordRegex.MatchString(object) {
				msg := fmt.Sprintf("Container Body not comply container policy: %s", object)
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin." + msg}
			} else {
				return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin." + object}
			}
		}
	}

	// here we mush to allow /containers/json?all=1, otherwise we'll stuck at endless loop because of checkDatabaseAndMakeMapa
	allowed, err := plugin.enforcer.Enforce(obj, act)
	if err != nil {
		log.Println(err)
		return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin. Error"}
	}

	if allowed {
		log.Println("obj:", obj, ", act:", act, "res: allowed")
		return authorization.Response{Allow: true}
	}
	if req.RequestHeaders["Authheader"] == os.Getenv("API_KEY") {
		log.Println("Bypass for admin")
		return authorization.Response{Allow: true}
	}

	// make here backdore for admin

	if strings.Contains(obj, "/containers/") {
		key, found := req.RequestHeaders["Authheader"]
		if !found {
			return authorization.Response{Allow: false, Msg: "Access denied by AuthPLugin. Authheader is Empty. Follow instruction - example.com"}
		}
		keyHash := calculateHash(key)

		err := CheckDatabaseAndMakeMapa()
		if err != nil {
			errorMsg := fmt.Sprintf("[CheckDatabaseAndMakeMapa] Error occurred: %e", err)
			log.Println(errorMsg)
		}

		partsOfApi := strings.Split(obj, "/")
		containerID := partsOfApi[2]
		isitNameOfContainer := false
		// is it a name of container
		for id := range nameAndIdMapping {
			if containerID == nameAndIdMapping[id] {
				isitNameOfContainer = true
				// redefining
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
			if !IsItShortId {
				return authorization.Response{Allow: true}
			}
		}

		containerID = containerID[:12]
		keyFromMapa, found := database[containerID]
		if found {
			if keyFromMapa == keyHash {
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

	if strings.Contains(obj, "/exec/") {
		key, found := req.RequestHeaders["Authheader"]
		if !found {
			return authorization.Response{Allow: false, Msg: "Access denied by auth plugin. Authheader is Empty. Follow instruction - example.com"}
		}
		partsOfApi := strings.Split(obj, "/")
		containerID := partsOfApi[2]
		isitNameOfContainer := false
		// is it a name of container
		for id := range nameAndIdMapping {
			if containerID == nameAndIdMapping[id] {
				isitNameOfContainer = true
				// redefining
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
			if !IsItShortId {
				return authorization.Response{Allow: true}
			}
		}
		containerID = containerID[:12]
		// can't exec at the container what doesn't exist
		keyFromMapa, found := database[containerID]
		if found {
			if keyFromMapa == key {
				return authorization.Response{Allow: true}
			} else {
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
