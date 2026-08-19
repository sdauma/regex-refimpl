package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// serverNet 单点接入监听：所有厂商的终端经由同一 TCP 端口接入，
// 连接对象以对端地址为键登记，供反向控制时检索。
// 该函数经整理后写入论文 §3.3 代码清单（教学简化版，省略 ch 通道与 StoreTime）。
func serverNet(addr string) {
	ch := make(chan string, 1024)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("单点监听已启动: %s", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		// 以对端地址为键，将连接对象存入并发映射；
		// 心跳或数据帧到达时，设备编码与该地址的对应关系
		// 由注册表一级维护，两级寻址在此汇合。
		mapConn.Store(conn.RemoteAddr().String(), conn)
		mapConnStoreTime.Store(conn.RemoteAddr().String(), unixNow())
		go handleConn(conn, ch)
	}
}

// handleConn 读取字节流，经帧定界与协议识别后分发至各厂商处理函数
func handleConn(conn net.Conn, ch chan<- string) {
	addr := conn.RemoteAddr().String()
	defer func() {
		mapConn.Delete(addr)
		mapConnStoreTime.Delete(addr)
		_ = conn.Close()
		log.Printf("连接关闭 %s", addr)
	}()
	sc := &frameScanner{}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sc.write(buf[:n])
			for {
				frame, ok := sc.next()
				if !ok {
					break
				}
				select {
				case ch <- frame:
				default:
				}
				dispatchFrame(conn, frame)
			}
		}
		if err != nil {
			return
		}
	}
}

// dispatchFrame 协议识别与分发：一次 identifyFrame 调用完成结构层
// 匹配、语义层校验与捕获组抽取，此后不再做第二次全文匹配。
func dispatchFrame(conn net.Conn, frame string) {
	code, name, sub, ok := identifyFrame(frame)
	addr := conn.RemoteAddr().String()
	if !ok {
		log.Printf("未识别帧（来自 %s）: %s", addr, trunc(frame))
		return
	}
	switch code {
	case 20:
		handleDEER(conn, sub, addr)
	case 300:
		handleBOSIDA(conn, sub, addr)
	default:
		// 识别级协议：提取地址域并登记在线状态
		if devCode, ok2 := genericDeviceCode(code, sub); ok2 {
			registry.register(devCode, addr)
			log.Printf("[%s] 识别帧并登记 %s（来自 %s）", name, devCode, addr)
		} else {
			log.Printf("[%s] 识别帧（来自 %s）: %s", name, addr, trunc(frame))
		}
	}
}

func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 9047, "终端接入 TCP 端口")
	rpcPort := fs.Int("rpc", 3388, "JSON-RPC 控制端口")
	regPath := fs.String("registry", "registry.json", "设备注册表路径")
	stale := fs.Duration("stale", defaultStale, "陈旧连接判定时长")
	_ = fs.Parse(args)

	registry = newDeviceRegistry(*regPath)
	registry.onRegister = func(code string) { pendingRetry(code) }
	stop := make(chan struct{})
	go janitor(*stale, stop)
	go rpcServe(*rpcPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
		os.Exit(0)
	}()

	serverNet(serverListenAddr(*port))
}

func serverListenAddr(port int) string {
	return net.JoinHostPort("", itoa(port))
}
