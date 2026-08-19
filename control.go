package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultStale   = 90 * time.Second
	pendingTTL     = 60 * time.Second
	ackTimeout     = 3 * time.Second
	controlWaitMax = 35 * time.Second
)

// ---------- 反向控制 ----------
//
// 链路：控制端 → JSON-RPC → 查注册表（设备编码→在线地址）
//       → 查连接映射（在线地址→连接对象）→ 连接对象写命令帧。
// 变 IP 过渡窗口内连接缺失时，命令进入暂存队列，
// 终端重拨并以新地址注册后自动重试，超时（60 秒）销毁。

type controlResult struct {
	Status  string        `json:"status"`
	Detail  string        `json:"detail"`
	Elapsed time.Duration `json:"-"`
	ElapsedMS float64     `json:"elapsedMs"`
}

type pendingCmd struct {
	code    string
	opening int
	expire  time.Time
	done    chan controlResult
}

var (
	ackWaiters sync.Map // addr -> chan string
	pendingMu  sync.Mutex
	pending    []*pendingCmd
)

func rpcServe(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  struct {
				Device  string `json:"device"`
				Opening int    `json:"opening"`
				Wait    bool   `json:"wait"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			rpcError(w, req.ID, -32700, "parse error")
			return
		}
		switch req.Method {
		case "control.setValve":
			res := controlSetValve(req.Params.Device, req.Params.Opening, req.Params.Wait)
			res.ElapsedMS = float64(res.Elapsed.Microseconds()) / 1000
			rpcResult(w, req.ID, res)
		case "debug.lookup":
			addr, ok := registry.lookup(req.Params.Device)
			if !ok {
				rpcError(w, req.ID, -32001, "device unknown")
				return
			}
			_, online := mapConn.Load(addr)
			rpcResult(w, req.ID, map[string]any{"addr": addr, "online": online})
		default:
			rpcError(w, req.ID, -32601, "method not found")
		}
	})
	addr := net.JoinHostPort("", itoa(port))
	log.Printf("JSON-RPC 控制接口已启动: %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func rpcResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func rpcError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": msg}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// controlSetValve 两级寻址与命令下发的主路径
func controlSetValve(code string, opening int, wait bool) controlResult {
	start := time.Now()
	if opening < 0 || opening > 100 {
		return controlResult{Status: "badparam", Detail: "开度须在 0–100 之间"}
	}
	addr, ok := registry.lookup(code)
	if !ok {
		return controlResult{Status: "unknown", Detail: "设备未注册（尚无任何上报）"}
	}
	if c, ok := mapConn.Load(addr); ok {
		conn, _ := c.(net.Conn)
		return sendValveCommand(conn, addr, code, opening, start)
	}
	// 在线地址已注册但连接对象缺失：处于变 IP 过渡窗口，
	// 命令暂存并等待下一次心跳注册时重试。
	pc := &pendingCmd{code: code, opening: opening,
		expire: time.Now().Add(pendingTTL), done: make(chan controlResult, 1)}
	pendingMu.Lock()
	pending = append(pending, pc)
	pendingMu.Unlock()
	if !wait {
		return controlResult{Status: "queued", Detail: "连接暂不可达，命令已暂存（60 秒）"}
	}
	select {
	case res := <-pc.done:
		res.Elapsed = time.Since(start)
		return res
	case <-time.After(controlWaitMax):
		return controlResult{Status: "expired", Detail: "暂存命令超过 60 秒未送达，已销毁"}
	}
}

func sendValveCommand(conn net.Conn, addr, code string, opening int, start time.Time) controlResult {
	cmd := bosidaControlCmd(valveAddrFromCode(code), opening)
	ackCh := make(chan string, 1)
	ackWaiters.Store(addr, ackCh)
	defer ackWaiters.Delete(addr)
	if _, err := conn.Write(hexToBytes(cmd)); err != nil {
		return controlResult{Status: "offline", Detail: "连接写入失败: " + err.Error(), Elapsed: time.Since(start)}
	}
	select {
	case <-ackCh:
		return controlResult{Status: "success", Detail: trunc(cmd), Elapsed: time.Since(start)}
	case <-time.After(ackTimeout):
		return controlResult{Status: "noack", Detail: "命令已下发，3 秒内未收到阀门应答", Elapsed: time.Since(start)}
	}
}

// pendingRetry 在设备以新地址完成注册后重试其暂存命令
func pendingRetry(code string) {
	pendingMu.Lock()
	rest := pending[:0]
	var fire []*pendingCmd
	for _, pc := range pending {
		if pc.code == code && time.Now().Before(pc.expire) {
			fire = append(fire, pc)
			continue
		}
		rest = append(rest, pc)
	}
	pending = rest
	pendingMu.Unlock()

	for _, pc := range fire {
		go func(pc *pendingCmd) {
			start := time.Now()
			addr, ok := registry.lookup(pc.code)
			if !ok {
				pc.done <- controlResult{Status: "unknown", Detail: "注册表查无此设备"}
				return
			}
			c, ok := mapConn.Load(addr)
			if !ok {
				// 仍未就绪：重新入队等待
				pendingMu.Lock()
				if time.Now().Before(pc.expire) {
					pending = append(pending, pc)
				}
				pendingMu.Unlock()
				return
			}
			res := sendValveCommand(c.(net.Conn), addr, pc.code, pc.opening, start)
			res.Elapsed = time.Since(pc.expire.Add(-pendingTTL)) // 自命令暂存起计时
			pc.done <- res
		}(pc)
	}
}

// cmdControl 命令行控制端：向 JSON-RPC 接口发起反向控制
func cmdControl(args []string) {
	fs := flag.NewFlagSet("control", flag.ExitOnError)
	device := fs.String("device", "", "设备编码（如 BSD-V-19271234001111）")
	opening := fs.Int("opening", 50, "目标开度百分比 0–100")
	rpc := fs.String("rpc", "http://127.0.0.1:3388", "JSON-RPC 地址")
	wait := fs.Bool("wait", true, "等待命令送达或超时")
	_ = fs.Parse(args)
	if *device == "" {
		log.Fatal("必须指定 -device")
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"control.setValve","params":{"device":%q,"opening":%d,"wait":%t}}`,
		*device, *opening, *wait)
	resp, err := http.Post(*rpc, "application/json", strings.NewReader(body))
	if err != nil {
		log.Fatalf("RPC 调用失败: %v", err)
	}
	defer resp.Body.Close()
	var out json.RawMessage
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Println(string(out))
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
