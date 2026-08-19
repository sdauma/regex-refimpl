package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"
)

// ---------- 终端模拟器 ----------
//
// 模拟终端按真实厂商协议规范的帧格式与集控平台通讯：
// 主动向单点端口发起 TCP 连接（模拟终端建链方向），
// 周期发送心跳与数据帧；支持以更换源地址的方式模拟
// 运营商回收 IP / 断电重启导致的变 IP 场景。

type simEvent struct {
	Kind   string // connected / heartbeat / report / rebind / ack / controlled / closed
	Detail string
	At     time.Time
}

type terminalSim struct {
	server    string
	bindIP    net.IP
	heartbeat time.Duration
	report    time.Duration
	events    chan<- simEvent
	conn      net.Conn
	stopCh    chan struct{}
}

func dialBound(server string, bindIP net.IP) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	if bindIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: bindIP}
	}
	return d.Dial("tcp", server)
}

func (t *terminalSim) emit(kind, detail string) {
	if t.events != nil {
		select {
		case t.events <- simEvent{Kind: kind, Detail: detail, At: time.Now()}:
		default:
		}
	}
}

func (t *terminalSim) send(frameHex string) error {
	_, err := t.conn.Write(hexToBytes(frameHex))
	return err
}

// readLoop 消费下行帧（平台确认帧 / 阀门控制命令）
func (t *terminalSim) readLoop(handleDown func(frame string, sub map[string]string)) {
	sc := &frameScanner{}
	buf := make([]byte, 1024)
	for {
		n, err := t.conn.Read(buf)
		if n > 0 {
			sc.write(buf[:n])
			for {
				frame, ok := sc.next()
				if !ok {
					break
				}
				if _, _, sub, ok2 := identifyFrame(frame); ok2 {
					handleDown(frame, sub)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (t *terminalSim) close() {
	if t.conn != nil {
		_ = t.conn.Close()
	}
	close(t.stopCh)
}

// nextIP 模拟运营商重新分配地址：127.0.0.x → 127.0.0.x+1
func nextIP(ip net.IP) net.IP {
	b := append([]byte(nil), ip.To4()...)
	b[3]++
	return net.IP(b)
}

// ---------- 德尔采集器模拟器 ----------

type deerSim struct {
	terminalSim
	cid      string
	meters   []deerMeter
	rng      *rand.Rand
}

func (s *deerSim) run(ctx context.Context, rebindAfter int) {
	beats := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := dialBound(s.server, s.bindIP)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		s.conn = conn
		s.emit("connected", s.bindIP.String())
		go s.readLoop(func(frame string, sub map[string]string) {
			if sub["cmd"] == deerCmdAck {
				s.emit("ack", "心跳已被平台确认")
			}
		})
		tick := time.NewTicker(s.heartbeat)
		repTick := time.NewTicker(s.report)
		stopped := false
		for !stopped {
			select {
			case <-ctx.Done():
				stopped = true
			case <-s.stopCh:
				stopped = true
			case <-tick.C:
				if err := s.send(deerHeartbeat(s.cid)); err != nil {
					stopped = true
					break
				}
				s.emit("heartbeat", fmt.Sprintf("第 %d 次心跳（源地址 %s）", beats+1, s.bindIP.String()))
				beats++
				if rebindAfter > 0 && beats == rebindAfter {
					// 模拟运营商回收 IP：断链 → 重拨延迟 → 新源地址重建连接
					s.emit("rebind", fmt.Sprintf("断链，将从 %s 重拨至 %s", s.bindIP.String(), nextIP(s.bindIP).String()))
					_ = conn.Close()
					time.Sleep(2 * time.Second)
					s.bindIP = nextIP(s.bindIP)
					stopped = true
				}
			case <-repTick.C:
				mutateMeters(s.meters, s.rng)
				if err := s.send(deerData(s.cid, s.meters, bcdNow())); err != nil {
					stopped = true
				}
			}
		}
		tick.Stop()
		repTick.Stop()
		_ = conn.Close()
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func mutateMeters(meters []deerMeter, rng *rand.Rand) {
	for i := range meters {
		meters[i].Heat += uint32(rng.Intn(20))
		meters[i].Flow += uint32(rng.Intn(15))
		meters[i].Power = uint32(400 + rng.Intn(600))
		meters[i].FlowRate = uint32(2000 + rng.Intn(3000))
		meters[i].Supply = uint32(3400 + rng.Intn(400))
		meters[i].ReturnT = uint32(3000 + rng.Intn(400))
		meters[i].Diff = meters[i].Supply - meters[i].ReturnT
		meters[i].Runtime++
	}
}

func cmdSimDeer(args []string) {
	fs := flag.NewFlagSet("simdeer", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:9047", "集控平台地址")
	bind := fs.String("bind", "127.0.0.2", "本地源地址（模拟终端出口 IP）")
	cid := fs.String("cid", "0A00", "采集器标识")
	beat := fs.Duration("heartbeat", 15*time.Second, "心跳周期")
	rep := fs.Duration("report", 45*time.Second, "数据上报周期")
	rebindAfter := fs.Int("rebindAfter", 0, "第 N 次心跳后模拟变 IP 重拨（0 表示不重拨）")
	duration := fs.Duration("duration", 5*time.Minute, "模拟运行时长")
	_ = fs.Parse(args)

	meters := []deerMeter{
		{Point: 1, Type: 1, Num: "10677965000000", Heat: 4100, Flow: 2919, Power: 1000,
			FlowRate: 8300, Supply: 3600, ReturnT: 3500, Diff: 110, Runtime: 84417},
		{Point: 2, Type: 1, Num: "7062219831000000"[0:14], Heat: 2892, Flow: 1688, Power: 800,
			FlowRate: 6100, Supply: 3600, ReturnT: 3520, Diff: 80, Runtime: 70160},
	}
	ev := make(chan simEvent, 256)
	s := &deerSim{
		terminalSim: terminalSim{server: *server, bindIP: net.ParseIP(*bind),
			heartbeat: *beat, report: *rep, events: ev, stopCh: make(chan struct{})},
		cid: *cid, meters: meters, rng: rand.New(rand.NewSource(1)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	go func() {
		for e := range ev {
			log.Printf("[模拟德尔 %s] %s %s", e.At.Format("15:04:05.000"), e.Kind, e.Detail)
		}
	}()
	s.run(ctx, *rebindAfter)
}

// ---------- 博思达阀门模拟器 ----------

type valveSim struct {
	terminalSim
	addr    string // 阀门地址（7 字节十六进制）
	opening int
}

func (v *valveSim) reportFrame() string {
	return bosidaBuildReport(bosidaReport{
		Addr: v.addr, T1: 9500, T2: 9400, Indoor: 2000, Setpoint: 2400,
		AccMin: 16442, AccHeat: 3699, TimeBCD: bcdNow(),
		Ctrl: 1, Mode: 0, State: 1, Opening: byte(v.opening), Fault: 0,
	})
}

func (v *valveSim) run(ctx context.Context, rebindAfter int) {
	reports := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := dialBound(v.server, v.bindIP)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		v.conn = conn
		v.emit("connected", v.bindIP.String())
		go v.readLoop(func(frame string, sub map[string]string) {
			if sub["cmd"] == bosidaCmdCtrl && len(sub["data"]) >= 8 {
				opening := int(hexVal2(sub["data"][6:8]))
				v.opening = opening
				ack := bosidaFrame("FEFE", v.addr, bosidaCmdAck, sub["data"][:6])
				_ = v.send(ack)
				v.emit("controlled", fmt.Sprintf("开度已设为 %d%%", opening))
			}
		})
		// 建链即上报一次（充当注册心跳）
		_ = v.send(v.reportFrame())
		reports++
		v.emit("report", fmt.Sprintf("上报 #1（源地址 %s）", v.bindIP.String()))
		tick := time.NewTicker(v.heartbeat)
		stopped := false
		for !stopped {
			select {
			case <-ctx.Done():
				stopped = true
			case <-v.stopCh:
				stopped = true
			case <-tick.C:
				if err := v.send(v.reportFrame()); err != nil {
					stopped = true
					break
				}
				reports++
				v.emit("report", fmt.Sprintf("上报 #%d（源地址 %s）", reports, v.bindIP.String()))
				if rebindAfter > 0 && reports == rebindAfter+1 {
					v.emit("rebind", fmt.Sprintf("断链，将从 %s 重拨至 %s", v.bindIP.String(), nextIP(v.bindIP).String()))
					_ = conn.Close()
					time.Sleep(2 * time.Second)
					v.bindIP = nextIP(v.bindIP)
					stopped = true
				}
			}
		}
		tick.Stop()
		_ = conn.Close()
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func cmdSimValve(args []string) {
	fs := flag.NewFlagSet("simvalve", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:9047", "集控平台地址")
	bind := fs.String("bind", "127.0.0.3", "本地源地址（模拟终端出口 IP）")
	addr := fs.String("addr", "19271234001111", "阀门地址（7 字节十六进制）")
	beat := fs.Duration("heartbeat", 15*time.Second, "心跳（上报）周期")
	rebindAfter := fs.Int("rebindAfter", 0, "第 N 次上报后模拟变 IP 重拨（0 表示不重拨）")
	duration := fs.Duration("duration", 5*time.Minute, "模拟运行时长")
	_ = fs.Parse(args)

	ev := make(chan simEvent, 256)
	v := &valveSim{
		terminalSim: terminalSim{server: *server, bindIP: net.ParseIP(*bind),
			heartbeat: *beat, events: ev, stopCh: make(chan struct{})},
		addr: *addr, opening: 50,
	}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	go func() {
		for e := range ev {
			log.Printf("[模拟博思达 %s] %s %s", e.At.Format("15:04:05.000"), e.Kind, e.Detail)
		}
	}()
	v.run(ctx, *rebindAfter)
}
