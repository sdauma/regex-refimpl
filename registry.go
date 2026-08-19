package main

import (
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"
)

// ---------- 两级寻址的地址侧 ----------
//
// 第一级：设备编码 → 在线地址（注册表）。终端每次上报心跳或数据帧时
// 自动登记/覆盖，反向控制前据此取得在线地址。
// 原型以 JSON 文件持久化；生产实现对应数据库表。
type deviceEntry struct {
	Code     string    `json:"code"`
	Addr     string    `json:"addr"`
	LastSeen time.Time `json:"lastSeen"`
}

type deviceRegistry struct {
	mu         sync.Mutex
	path       string
	m          map[string]deviceEntry
	onRegister func(code string)
}

var registry *deviceRegistry

func newDeviceRegistry(path string) *deviceRegistry {
	r := &deviceRegistry{path: path, m: map[string]deviceEntry{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &r.m)
	}
	return r
}

// register 上报即注册：新地址自动覆盖旧值——变 IP 场景下的关键路径
func (r *deviceRegistry) register(code, addr string) {
	r.mu.Lock()
	r.m[code] = deviceEntry{Code: code, Addr: addr, LastSeen: time.Now()}
	b, _ := json.MarshalIndent(r.m, "", " ")
	_ = os.WriteFile(r.path, b, 0o644)
	hook := r.onRegister
	r.mu.Unlock()
	if hook != nil {
		hook(code)
	}
}

func (r *deviceRegistry) lookup(code string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[code]
	return e.Addr, ok
}

// ---------- 两级寻址的连接侧 ----------
//
// 第二级：在线地址 → 连接对象。以对端地址为键将连接对象存入并发映射；
// mapConnStoreTime 记录登记时刻，供陈旧连接清理（janitor）使用。
var (
	mapConn          sync.Map // addr -> net.Conn
	mapConnStoreTime sync.Map // addr -> int64（Unix 秒）
)

// janitor 周期清理静默超过 stale 时长的连接。
// 半开连接（对端断电/IP 变更且未发 FIN）由写失败或本清理暴露，
// 映射项删除后，反向控制自然回退到命令暂存路径。
func janitor(stale time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			now := time.Now().Unix()
			mapConnStoreTime.Range(func(k, v any) bool {
				addr, ts := k.(string), v.(int64)
				if now-ts > int64(stale.Seconds()) {
					if c, ok := mapConn.Load(addr); ok {
						if conn, ok2 := c.(net.Conn); ok2 {
							_ = conn.Close() // handleConn 的 defer 负责删除两侧映射项
						}
					}
				}
				return true
			})
		}
	}
}
