package plugin

import (
	"encoding/json"
	fmt2 "fmt"
	"log"
	"testing"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/stretchr/testify/assert"
)

type AdmitTestCase struct {
	name    string
	body    map[string]string
	request authorization.Request
	result  authorization.Response
}

// go test -count 100 -coverprofile=/tmp/coverage.out ./...
func TestAuthZReq(t *testing.T) {
	authPlugin := &CasbinAuthZPlugin{}
	testContainerID := "f760a15e19af19f97e52ead30d4cb5f8c906e601bab8cb63ccc071857df44b75"
	testContainerNAME := "test_container"

	testCases := []AdmitTestCase{
		{
			name: "Test creation a volumes",
			body: map[string]string{"Driver": "local"},
			request: authorization.Request{
				RequestURI:     "/v1.42/volumes/create",
				RequestMethod:  "POST",
				RequestHeaders: map[string]string{"AuthHeader": "e51cc6373acd45d624e930cb8162cbcc", "Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: false, Msg: "Access denied by AuthPlugin: /volumes/create", Err: ""},
		},
		{
			name: "Test commit a container",
			request: authorization.Request{
				RequestURI:     "/v1.42/commit?author=&comment=&container=5hae354g3&repo=&tag=",
				RequestMethod:  "POST",
				RequestHeaders: map[string]string{"AuthHeader": "e51cc6373acd45d624e930cb8162cbcc", "Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: false, Msg: "Access denied by AuthPlugin: /commit?author=&comment=&container=5hae354g3&repo=&tag=", Err: ""},
		},
		{
			name: "Test actions with a plugin",
			request: authorization.Request{
				RequestURI:     "/v1.41/plugins",
				RequestMethod:  "GET",
				RequestHeaders: map[string]string{"AuthHeader": "e51cc6373acd45d624e930cb8162cbcc", "Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: false, Msg: "Access denied by AuthPlugin: /plugins", Err: ""},
		},
		{
			name: "Test /_ping",
			request: authorization.Request{
				RequestURI:     "/_ping",
				RequestMethod:  "HEAD",
				RequestHeaders: map[string]string{"Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: true, Msg: "", Err: ""},
		},
		{
			name: "Test docker ps -a",
			request: authorization.Request{
				RequestURI:     "/v1.41/containers/json?all=1",
				RequestMethod:  "GET",
				RequestHeaders: map[string]string{"Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: true, Msg: "", Err: ""},
		},
		{
			name: "Forget AuthHeader",
			request: authorization.Request{
				RequestURI:     "/v1.41/containers/6401e251495ad7223ce84d95/stop",
				RequestMethod:  "POST",
				RequestHeaders: map[string]string{"Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: false, Msg: "Access denied by AuthPlugin. AuthHeader is Empty. Follow the instruction - https://docs.docker.com/engine/reference/commandline/cli/#custom-http-headers", Err: ""},
		},
		{
			name: "User1 want to start his own container",
			request: authorization.Request{
				RequestURI:     "/v1.41/containers/" + testContainerID + "/start",
				RequestMethod:  "POST",
				RequestHeaders: map[string]string{"AuthHeader": "0880d90d56bdcb9ad90aec20707b30e1", "Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: true, Msg: "", Err: ""},
		},
		{
			name: "Culprit1 want to stop User1 container",
			request: authorization.Request{
				RequestURI:     "/v1.41/containers/" + testContainerID + "/stop",
				RequestMethod:  "POST",
				RequestHeaders: map[string]string{"AuthHeader": "8ef277362c22393721a37b974fe4e902", "Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: false, Msg: "Access denied by AuthPlugin. That's not your container", Err: ""},
		},
		{
			name: "Culprit1 want to stop User1 container via name",
			request: authorization.Request{
				RequestURI:     "/v1.41/containers/" + testContainerNAME + "/stop",
				RequestMethod:  "POST",
				RequestHeaders: map[string]string{"AuthHeader": "8ef277362c22393721a37b974fe4e902", "Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: false, Msg: "Access denied by AuthPlugin. That's not your container", Err: ""},
		},
		{
			name: "Culprit1 want to exec User1 container",
			request: authorization.Request{
				RequestURI:     "/v1.41/exec/" + testContainerID + "/start",
				RequestMethod:  "POST",
				RequestHeaders: map[string]string{"AuthHeader": "8ef277362c22393721a37b974fe4e902", "Content-Type": "application/json"},
			},
			result: authorization.Response{
				Allow: false, Msg: "Access denied by AuthPlugin. You can't exec other people's containers", Err: ""},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {

			data, err := json.Marshal(testCase.body)
			if err != nil {
				errorMsg := fmt2.Sprintf("Can't Marshal data %e", err)
				log.Println(errorMsg)
			}

			testCase.request.RequestBody = data
			resp := authPlugin.AuthZReq(testCase.request)
			assert.Equal(t, testCase.result, resp)
		})
	}
}
