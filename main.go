package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	commands := map[string]func([]string){
		"server":     cmdServer,
		"simdeer":    cmdSimDeer,
		"simvalve":   cmdSimValve,
		"control":    cmdControl,
		"experiment": cmdExperiment,
	}
	args := os.Args
	if len(args) < 2 {
		usage(commands)
		return
	}
	if f, ok := commands[args[1]]; ok {
		f(args[2:])
		return
	}
	usage(commands)
}

func usage(commands map[string]func([]string)) {
	fmt.Println(`regex-refimpl —— 基于正则表达式匹配的异构终端单点集控参考实现

用法:
  regex-refimpl server    [-port 9047] [-rpc 3388] [-registry registry.json] [-stale 90s]
  regex-refimpl simdeer   [-server 127.0.0.1:9047] [-bind 127.0.0.2] [-cid 0A00]
                    [-heartbeat 15s] [-report 45s] [-rebindAfter N] [-duration 5m]
  regex-refimpl simvalve  [-server 127.0.0.1:9047] [-bind 127.0.0.3] [-addr 19271234001111]
                    [-heartbeat 15s] [-rebindAfter N] [-duration 5m]
  regex-refimpl control   -device BSD-V-19271234001111 -opening 50 [-rpc http://127.0.0.1:3388]
  regex-refimpl experiment accuracy|ipchange|bench`)
}

func unixNow() int64 { return time.Now().Unix() }

func netParseIP(s string) net.IP { return net.ParseIP(s) }

func filepathJoin(dir, name string) string { return filepath.Join(dir, name) }

func postControl(url, body string) controlResult {
	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	if err != nil {
		return controlResult{Status: "rpcfail", Detail: err.Error()}
	}
	defer resp.Body.Close()
	var out struct {
		Result controlResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return controlResult{Status: "rpcfail", Detail: err.Error()}
	}
	if out.Error != nil {
		return controlResult{Status: "rpcerror", Detail: out.Error.Message}
	}
	return out.Result
}
