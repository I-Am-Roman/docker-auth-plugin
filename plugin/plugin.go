// Copyright 2019 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"context"
	"encoding/json"
	"log"
	"net/url"
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

func checkDatabaseAndMakeMapa() error {
	log.Println("INside checkDatabaseAndMakeMapa")
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return err
	}
	log.Println("[Containers]:", containers)

	for _, container := range containers {
		// Does Not exist another way? What about time?
		for d := range nameAndIdMapping {
			delete(nameAndIdMapping, d)
		}
		log.Println(container.ID)
		log.Println(container.Names[0])
		// took only 12 symbols
		ID := container.ID[:12]
		// docker daemon usually retuen /<nameOfContainer>
		name := container.Names[0]
		hasSlash := strings.Contains(name, "/")
		if hasSlash {
			name = strings.TrimLeft(name, "/")
		}
		nameAndIdMapping[ID] = name
	}

	for containerID := range database {
		_, found := nameAndIdMapping[containerID]
		if found {
			continue
		} else {
			delete(database, containerID)
		}
	}
	return nil
}

// AuthZReq authorizes the docker client command.
// The command is allowed only if it matches a Casbin policy rule.
// Otherwise, the request is denied!
func (plugin *CasbinAuthZPlugin) AuthZReq(req authorization.Request) authorization.Response {
	// Parse request and the request body
	log.Println("------------------------------------------------------------------")
	reqURI, _ := url.QueryUnescape(req.RequestURI)
	reqURL, _ := url.ParseRequestURI(reqURI)

	// if we'll get empty request to docker
	if reqURL == nil {
		return authorization.Response{Allow: false, Msg: "Access denied by auth plugin. Emtpy request"}
	}

	headersJSON, err := json.Marshal(req.RequestHeaders)
	obj2 := reqURL.String()
	reqBody, _ := url.QueryUnescape(string(req.RequestBody))
	act2 := req.RequestMethod

	var headers map[string]string
	err = json.Unmarshal(headersJSON, &headers)
	// does i need use panic?
	if err != nil {
		log.Println("Error marshling headers to JSON:", err)
	}

	log.Println("Headers:", headers)
	log.Println("Method:", act2)
	log.Println("Api:", obj2)
	log.Println("Body:", reqBody)

	key, found := headers["Authheader"]

	if found {
		log.Println("OK! I've found Authheader")
		log.Println("key: ", key)
	}

	obj1 := reqURL.String()

	//------------------------------------------
	// DEBUG
	if obj1 == "/v1.43/containers/create" {
		reqBody, _ := url.QueryUnescape(string(req.RequestBody))
		log.Println("[create container]:", reqBody)
	}
	//------------------------------------------

	obj := reqURL.String()
	act := req.RequestMethod

	if strings.Contains(obj, "/v1.43/containers/") {

		err := checkDatabaseAndMakeMapa()
		if err != nil {
			log.Println("Error occurred", err)
		}

		parts := strings.Split(obj, "/")
		containerID := parts[3]
		isitNameOfContainer := false
		for id := range nameAndIdMapping {
			if containerID == nameAndIdMapping[id] {
				log.Println("Name of container:", nameAndIdMapping[id])
				isitNameOfContainer = true
				containerID = id
				break
			}
		}
		// containerID , isitNameOfContainer = nameAndIdMapping[containerID]
		if len(containerID) != 64 && len(containerID) != 12 && !isitNameOfContainer {
			return authorization.Response{Allow: true}
		}

		containerID = containerID[:12]

		log.Println("Container ID:", containerID)
		keyFromMapa, found := database[containerID]
		log.Println("keyFromMapa:", keyFromMapa)
		if found {
			if keyFromMapa == key {
				log.Println("keyFromMapa equal key")
				return authorization.Response{Allow: true}
			} else {
				return authorization.Response{Allow: false, Msg: "Access denied by casbin plugin. That's not your container"}
			}
		} else {
			log.Println("That's container was created right now:", containerID)
			database[containerID] = key
			return authorization.Response{Allow: true}
		}
	}

	if strings.Contains(obj, "/v1.43/exec/") {
		parts := strings.Split(obj, "/")
		containerID := parts[3]
		// can't exec at the container what doesn't exist
		keyFromMapa, found := database[containerID]
		log.Println("keyFromMapa:", keyFromMapa)
		if found {
			if keyFromMapa == key {
				log.Println("Database:", database)
				return authorization.Response{Allow: true}
			} else {
				return authorization.Response{Allow: false, Msg: "Access denied by casbin plugin"}
			}
		}
	}

	// Check rules from the config. [Denied all what not allow]. Need to check in the end?
	allowed, err := plugin.enforcer.Enforce(obj, act)
	if err != nil {
		log.Println(err)
		return authorization.Response{Allow: false, Msg: "Access denied by auth plugin. "}
	}

	if allowed {
		log.Println("obj:", obj, ", act:", act, "res: allowed")
		return authorization.Response{Allow: true}
	}

	log.Println("ALLOW ALL")
	return authorization.Response{Allow: true}
}

// AuthZRes authorizes the docker client response.
// All responses are allowed by default.
func (plugin *CasbinAuthZPlugin) AuthZRes(req authorization.Request) authorization.Response {
	// Allowed by default.
	return authorization.Response{Allow: true}
}
