package containerpolicy

import (
	"encoding/json"
	fmt2 "fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Result struct {
	answer bool
	msg    string
}

type AdmitTestCase struct {
	name   string
	body   map[string]interface{}
	result Result
}

func TestComplyTheContainerPolicy(t *testing.T) {

	testCases := []AdmitTestCase{
		{
			name: "Good container",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"PublishAllPorts":  false,
				"Privileged":       false,
				"ReadonlyRootfs":   false,
			},
			result: Result{true, ""},
		},
		{
			name: "Privileged container",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"PublishAllPorts":  false,
				"Privileged":       true,
				"ReadonlyRootfs":   false,
			},
			result: Result{answer: false, msg: "privileged"},
		},
		{
			name: "Privileged container try to bypass",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"Privileged":       false,
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"PublishAllPorts":  false,
				"privileged":       true,
				"ReadonlyRootfs":   false,
			},
			result: Result{answer: false, msg: "privileged"},
		},
		{
			name: "NetworkMode:host container",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"Privileged":       false,
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"PublishAllPorts":  false,
				"NetworkMode":      "host",
			},
			result: Result{answer: false, msg: "networkmode"},
		},
		{
			name: "Good NetworkMode container",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"Privileged":       false,
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"PublishAllPorts":  false,
				"NetworkMode":      "default",
			},
			result: Result{answer: true, msg: ""},
		},
		{
			name: "Turn off apparmor",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"SecurityOpt":      []string{"apparmor=unconfined"},
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"PublishAllPorts":  false,
				"NetworkMode":      "",
			},
			result: Result{answer: false, msg: "securityopt"},
		},
		{
			name: "Not allowed binds",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"SecurityOpt":      []string{},
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"Binds":            []string{"/home/user/someFile.txt:/app"},
				"NetworkMode":      "",
			},
			result: Result{answer: false, msg: "binds"},
		},
		{
			name: "Allowed binds",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"SecurityOpt":      "",
				"OomScoreAdj":      500,
				"PidMode":          "",
				"PidsLimit":        0,
				"PortBindings":     "{}",
				"Binds":            []string{"/var/run/docker.sock:/var/run/docker.sock"},
				"NetworkMode":      "",
			},
			result: Result{answer: true, msg: ""},
		},
		{
			name: "Allowed binds, but using forbidden binds",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"SecurityOpt":      "",
				"OomScoreAdj":      500,
				"PidMode":          "",
				"IpcMode":          "",
				"PortBindings":     "{}",
				"Binds":            []string{"/var/run/docker.sock:/var/run/docker.sock", "/:/host/"},
				"NetworkMode":      "",
			},
			result: Result{answer: false, msg: "binds"},
		},
		{
			name: "Try to bypass IpcMode",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"SecurityOpt":      "",
				"OomScoreAdj":      500,
				"PidMode":          "",
				"IpcMode":          "none",
				"ipcMode":          "host",
				"PortBindings":     "{}",
				"Binds":            []string{},
				"NetworkMode":      "",
			},
			result: Result{answer: false, msg: "ipcmode"},
		},
		{
			name: "Good IpcMode container",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"SecurityOpt":      "",
				"OomScoreAdj":      500,
				"PidMode":          "",
				"IpcMode":          "none",
				"PortBindings":     "{}",
				"NetworkMode":      "",
			},
			result: Result{answer: true, msg: ""},
		},
		{
			name: "Try to bypass Devices",
			body: map[string]interface{}{
				"MemorySwappiness": 60,
				"OomKillDisable":   false,
				"SecurityOpt":      "",
				"OomScoreAdj":      500,
				"PidMode":          "",
				"IpcMode":          "none",
				"Devices":          []string{"/app/overload"},
				"NetworkMode":      "",
			},
			result: Result{answer: false, msg: "devices"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {

			jsonString, err := json.Marshal(testCase.body)
			if err != nil {
				fmt2.Println("Error during Marshal into JSON:", err)
				return
			}
			response, msg := ComplyTheContainerPolicy(string(jsonString))
			assert.Equal(t, testCase.result, Result{response, msg})
		})
	}
}
