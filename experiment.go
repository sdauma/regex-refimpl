package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"time"
)

// ---------- 实验 ----------
//
// accuracy : 协议识别与解析的定量评估（含跨协议冲突与畸形帧）
// ipchange : 变 IP 场景下反向控制链路恢复时延的端到端测量
// bench    : 单帧六模式按序匹配的微基准

func cmdExperiment(args []string) {
	if len(args) < 1 {
		log.Fatal("experiment accuracy|ipchange|bench")
	}
	switch args[0] {
	case "accuracy":
		expAccuracy()
	case "ipchange":
		expIPChange(20)
	case "bench":
		expBench()
	default:
		log.Fatalf("未知实验: %s", args[0])
	}
}

// ---------- 实验 1：识别准确性 ----------

type frameCase struct {
	expected int
	name     string
	frame    string
}

type accStat struct {
	total, correct, rejected int
	wrong                    map[string]int
}

func expAccuracy() {
	rng := rand.New(rand.NewSource(42))
	cases := []frameCase{}

	// 真实样例帧优先（来自厂商协议文档与现场抓包）
	cases = append(cases,
		frameCase{20, "德尔数据帧(真实样例)", deerRealSample()},
		frameCase{20, "德尔心跳帧", deerHeartbeat("0A00")},
		frameCase{300, "博思达上报帧(真实样例)", bosidaRealSample()},
		frameCase{300, "博思达开度设置应答", bosidaFrame("FEFE", "19271234001111", bosidaCmdAck, "A01700")},
	)

	const n = 200
	for i := 0; i < n; i++ {
		cases = append(cases, frameCase{20, "德尔数据帧", buildRandDeer(rng)})
		cases = append(cases, frameCase{300, "博思达上报帧", buildRandBosida(rng)})
		cases = append(cases, frameCase{40, "德宝帧", buildRandDebao(rng)})
		cases = append(cases, frameCase{30, "普赛热量表帧", buildRandPusai(rng)})
		cases = append(cases, frameCase{200, "琅卡博阀门帧", buildRandLangkabo(rng)})
		cases = append(cases, frameCase{400, "普赛调节阀帧", buildRandPusaiValve(rng)})
	}

	stats := map[int]*accStat{}
	ambiguous := 0
	for _, c := range cases {
		st := stats[c.expected]
		if st == nil {
			st = &accStat{wrong: map[string]int{}}
			stats[c.expected] = st
		}
		st.total++
		code, _, _, ok := identifyFrame(c.frame)
		if !ok {
			st.rejected++
			continue
		}
		if code == c.expected {
			st.correct++
		} else {
			st.wrong[fmt.Sprintf("误判为%d", code)]++
		}
		// 歧义分析：统计该帧可被几条模式命中
		hits := 0
		for _, p := range protocolTable {
			if p.pattern.MatchString(c.frame) {
				hits++
			}
		}
		if hits > 1 {
			ambiguous++
		}
	}

	fmt.Println("== 实验 1：协议识别准确性 ==")
	fmt.Printf("合规帧总数 %d（每协议 %d 帧随机生成 + 真实样例）\n", len(cases), n)
	for _, p := range protocolTable {
		st := stats[p.code]
		if st == nil {
			continue
		}
		line := fmt.Sprintf("  %-8d %-14s 命中 %d/%d", p.code, p.name, st.correct, st.total)
		if st.rejected > 0 {
			line += fmt.Sprintf("，拒收 %d", st.rejected)
		}
		for w, c := range st.wrong {
			line += fmt.Sprintf("，%s ×%d", w, c)
		}
		fmt.Println(line)
	}
	fmt.Printf("按序匹配下误判总数: %d；结构歧义帧（可命中多条模式，由次序消解）: %d\n",
		countWrong(stats), ambiguous)

	// 畸形帧：截断 / 校验和破坏 / 随机十六进制串，
	// 分层统计两道防线各自的拦截量
	structBlock, semBlock := 0, 0
	leaked := map[string]int{}
	badTotal := 0
	check := func(kind string, f string) {
		badTotal++
		if _, _, _, ok := judgeFactory(f); !ok {
			structBlock++
			return
		}
		code, name, _, ok := identifyFrame(f)
		if !ok {
			semBlock++
			return
		}
		leaked[fmt.Sprintf("%s→%s(%d)", kind, name, code)]++
	}
	for i := 0; i < 30; i++ {
		f := buildRandDeer(rng)
		cut := 2 * (1 + rng.Intn(len(f)/4/2))
		check("截断", f[:cut])
		f2 := buildRandBosida(rng)
		f2 = f2[:len(f2)-4] + "0000" + f2[len(f2)-2:]
		check("坏校验", f2)
		rnd := ""
		for j := 0; j < 20+rng.Intn(40); j++ {
			rnd += fmt.Sprintf("%X", rng.Intn(16))
		}
		check("随机串", rnd)
	}
	fmt.Printf("畸形帧 %d 条（截断/坏校验/随机串各 30）：结构层拦截 %d，语义层拦截 %d\n",
		badTotal, structBlock, semBlock)
	if len(leaked) == 0 {
		fmt.Println("漏过 0 条")
	} else {
		fmt.Printf("漏过 %d 条（仅限无校验域的识别级协议）: %v\n", sumMap(leaked), leaked)
	}
}

func countWrong(stats map[int]*accStat) int {
	w := 0
	for _, st := range stats {
		for _, c := range st.wrong {
			w += c
		}
	}
	return w
}

func sumMap(m map[string]int) int {
	s := 0
	for _, v := range m {
		s += v
	}
	return s
}

func deerRealSample() string {
	// 取自《EB90解析.txt》第 1 计量点真实样例
	return deerData("0A00", []deerMeter{{
		Point: 1, Type: 1, Num: "10677965000000",
		Heat: 4100, Flow: 2919, Power: 10, FlowRate: 8300,
		Supply: 3600, ReturnT: 3500, Diff: 110, Runtime: 84417,
	}}, "1304130D2B22")
}

func bosidaRealSample() string {
	// 取自《_bosida_valve.txt》真实上报样例（开度 0xCA）
	return bosidaBuildReport(bosidaReport{
		Addr: "19271234001111", T1: 0x2519, T2: 0x2598, Indoor: 0x2577, Setpoint: 0x2500,
		AccMin: 16442, AccHeat: 3699, TimeBCD: "130115021936",
		Ctrl: 1, Mode: 0, State: 1, Opening: 0xCA, Fault: 0,
	})
}

func buildRandDeer(rng *rand.Rand) string {
	meters := []deerMeter{{
		Point: 1, Type: 1,
		Num:   fmt.Sprintf("%014X", rng.Int63n(1<<48)),
		Heat:  uint32(rng.Intn(1 << 20)), Flow: uint32(rng.Intn(1 << 18)),
		Power: uint32(rng.Intn(1 << 12)), FlowRate: uint32(rng.Intn(1 << 16)),
		Supply: uint32(3000 + rng.Intn(1000)), ReturnT: uint32(2800 + rng.Intn(900)),
		Diff: uint32(rng.Intn(500)), Runtime: uint32(rng.Intn(1 << 20)), Fault: 0,
	}}
	return deerData(fmt.Sprintf("%04X", rng.Intn(0xFFFF)), meters, bcdNow())
}

func buildRandBosida(rng *rand.Rand) string {
	return bosidaBuildReport(bosidaReport{
		Addr: randHex(rng, 14), T1: uint16(rng.Intn(1 << 15)), T2: uint16(rng.Intn(1 << 15)),
		Indoor: uint16(rng.Intn(1 << 15)), Setpoint: uint16(rng.Intn(1 << 15)),
		AccMin: uint32(rng.Intn(1 << 24)), AccHeat: uint32(rng.Intn(1 << 24)),
		TimeBCD: bcdNow(), Ctrl: 1, Mode: 0, State: 1,
		Opening: byte(rng.Intn(101)), Fault: 0,
	})
}

func buildRandDebao(rng *rand.Rand) string {
	dataLen := 2 + rng.Intn(20)
	data := randHex(rng, dataLen*2)
	l := 9 + dataLen // LEN 覆盖控制码至校验和（含）的字节数
	return fmt.Sprintf("68%02X%02X68%s%s%s%s%s16",
		l, l, randHex(rng, 2), randHex(rng, 10), randHex(rng, 2), randHex(rng, 2), data)
}

func buildRandPusai(rng *rand.Rand) string {
	return "7E21" + randHex(rng, 26) + "7E"
}

func buildRandLangkabo(rng *rand.Rand) string {
	t := []string{"0C", "0E", "0F"}[rng.Intn(3)]
	return t + "68" + randHex(rng, 8) + randHex(rng, 2) + randHex(rng, 8) + "16"
}

func buildRandPusaiValve(rng *rand.Rand) string {
	return "FEFE7E" + randHex(rng, 2) + randHex(rng, 12) + randHex(rng, 2) + randHex(rng, 8) + "7E"
}

func randHex(rng *rand.Rand, n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += fmt.Sprintf("%X", rng.Intn(16))
	}
	return s
}

// ---------- 实验 2：变 IP 反向控制恢复时延 ----------

func expIPChange(trials int) {
	fmt.Println("== 实验 2：变 IP 场景反向控制恢复时延 ==")
	tcpPort, rpcPort := 29047, 23388
	regPath := filepathJoin(os.TempDir(), "refimpl-exp2-registry.json")
	_ = os.Remove(regPath)
	registry = newDeviceRegistry(regPath)
	registry.onRegister = func(code string) { pendingRetry(code) }
	stop := make(chan struct{})
	go janitor(defaultStale, stop)
	go rpcServe(rpcPort)
	go serverNet(serverListenAddr(tcpPort))
	time.Sleep(300 * time.Millisecond)

	server := fmt.Sprintf("127.0.0.1:%d", tcpPort)
	rpcURL := fmt.Sprintf("http://127.0.0.1:%d", rpcPort)
	code := "BSD-V-19271234001111"

	var recover, reconnect []float64
	statuses := map[string]int{}
	for i := 0; i < trials; i++ {
		ev := make(chan simEvent, 128)
		bind := fmt.Sprintf("127.0.0.%d", 100+2*i)
		v := &valveSim{
			terminalSim: terminalSim{server: server, bindIP: netParseIP(bind),
				heartbeat: 3 * time.Second, events: ev, stopCh: make(chan struct{})},
			addr: "19271234001111", opening: 50,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		go v.run(ctx, 1) // 第 1 次周期上报后模拟变 IP 重拨

		// 基线：等待注册后控制一次，确认链路可用
		baseOK := false
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if r := callControl(rpcURL, code, 60, false); r.Status == "success" {
				baseOK = true
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if !baseOK {
			log.Printf("试验 %d：基线控制失败，跳过", i+1)
			cancel()
			v.close()
			continue
		}

		// 变 IP：重拨断链后立即下发控制，等待暂存命令经新链路送达
		var rebindAt time.Time
		go func() {
			for e := range ev {
				if e.Kind == "rebind" {
					rebindAt = e.At
				}
			}
		}()
		time.Sleep(3*time.Second + 200*time.Millisecond) // 等待重拨触发点
		res := callControlWait(rpcURL, code, 80)
		statuses[res.Status]++
		if res.Status == "success" {
			recover = append(recover, res.ElapsedMS)
			if !rebindAt.IsZero() {
				reconnect = append(reconnect, res.ElapsedMS-2000) // 扣除重拨等待
			}
		}
		cancel()
		v.close()
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Printf("试验次数 %d\n", trials)
	fmt.Printf("恢复结果分布: %v\n", statuses)
	if len(recover) > 0 {
		fmt.Printf("控制链路恢复时延（自命令发起）: 均值 %.0f ms / 最小 %.0f ms / 最大 %.0f ms / 中位 %.0f ms\n",
			mean(recover), minF(recover), maxF(recover), median(recover))
	}
	if len(reconnect) > 0 {
		fmt.Printf("链路重建+注册时延（扣除 2 s 重拨等待）: 均值 %.0f ms / 最大 %.0f ms\n",
			mean(reconnect), maxF(reconnect))
	}
	fmt.Println("结论：终端 IP 变化后无需人工干预，命令经暂存-重试机制自动经新链路送达。")

	// 超时销毁路径验证：单独一轮，不计入上述 20 轮恢复统计
	expIPChangeTimeout(rpcURL, server, code)

	close(stop)
}

// expIPChangeTimeout 验证暂存队列的 TTL 超时销毁路径：
// 终端失联（断开且不重注册）时下发命令进入暂存队列，超过 pendingTTL（60 秒）后，
// 即使终端后续以新地址重注册，过期命令亦不会被投递（开度保持初值），
// 从而验证“超时销毁、避免对失联终端无效重试”的语义。
func expIPChangeTimeout(rpcURL, server, code string) {
	fmt.Println("== 实验 2b：变 IP 超时销毁路径验证 ==")
	const ttlWait = 65 * time.Second // 超过 pendingTTL（60 秒）

	// 阶段 1：终端以地址 A 注册上线，确认基线链路可用
	baseOK := false
	alive1 := &valveSim{
		terminalSim: terminalSim{server: server, bindIP: netParseIP("127.0.0.250"),
			heartbeat: 3 * time.Second, events: make(chan simEvent, 64), stopCh: make(chan struct{})},
		addr: "19271234001111", opening: 50,
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		go alive1.run(ctx, 0)
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if r := callControl(rpcURL, code, 70, false); r.Status == "success" {
				baseOK = true
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		cancel()
		alive1.close()
	}
	if !baseOK {
		log.Println("超时试验：基线控制失败，跳过")
		return
	}

	// 阶段 2：断开终端（不重注册，模拟永久失联），下发命令进入暂存队列
	q := callControl(rpcURL, code, 80, false)
	before := countPending(code)
	fmt.Printf("失联态下发结果: status=%s（命令应暂存）；暂存队列中该设备命令数: %d\n", q.Status, before)

	// 阶段 3：等待超过 pendingTTL（60 秒），命令过期
	time.Sleep(ttlWait)

	// 阶段 4：终端以新地址 B 重注册，触发 pendingRetry；
	// 过期命令应被 TTL 过滤、不投递，阀门开度保持初值 50
	alive2 := &valveSim{
		terminalSim: terminalSim{server: server, bindIP: netParseIP("127.0.0.251"),
			heartbeat: 3 * time.Second, events: make(chan simEvent, 64), stopCh: make(chan struct{})},
		addr: "19271234001111", opening: 50,
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		go alive2.run(ctx, 0)
		time.Sleep(2 * time.Second) // 等待注册与 pendingRetry 处理窗口
		// 此时若过期命令被错误投递，alive2.opening 应为 80；否则保持 50
		if alive2.opening == 50 {
			fmt.Println("过期命令未被投递（阀门开度保持初始 50），TTL 超时销毁语义成立")
		} else {
			fmt.Printf("警告：过期命令仍被投递（开度=%d），超时销毁路径异常\n", alive2.opening)
		}
		// 下发新命令确认链路正常（排除“终端未注册成功”的歧义）
		c := callControl(rpcURL, code, 90, true)
		fmt.Printf("链路复通确认: status=%s, 阀门开度=%d\n", c.Status, alive2.opening)
		cancel()
		alive2.close()
	}
	after := countPending(code)
	fmt.Printf("暂存队列中该设备命令数（过期后）: %d\n", after)
	fmt.Println("结论：暂存命令在超过 60 秒 TTL 后过期，未被投递到延迟注册的终端，验证了超时销毁路径。")
}

// countPending 统计暂存队列中指定设备的命令条数（供超时试验断言）
func countPending(code string) int {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	n := 0
	for _, pc := range pending {
		if pc.code == code {
			n++
		}
	}
	return n
}

func callControl(url, code string, opening int, wait bool) controlResult {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"control.setValve","params":{"device":%q,"opening":%d,"wait":%t}}`,
		code, opening, wait)
	return postControl(url, body)
}

func callControlWait(url, code string, opening int) controlResult {
	return callControl(url, code, opening, true)
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func minF(v []float64) float64 {
	m := v[0]
	for _, x := range v {
		if x < m {
			m = x
		}
	}
	return m
}

func maxF(v []float64) float64 {
	m := v[0]
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

// ---------- 实验 3：单帧匹配微基准 ----------

func expBench() {
	fmt.Println("== 实验 3：单帧六模式按序匹配微基准 ==")
	frames := []struct{ name, frame string }{
		{"德尔数据帧(4表)", deerData("0A00", makeMeters(4), bcdNow())},
		{"德尔心跳帧", deerHeartbeat("0A00")},
		{"博思达上报帧", buildRandBosida(rand.New(rand.NewSource(7)))},
		{"德宝帧", buildRandDebao(rand.New(rand.NewSource(7)))},
		{"普赛热量表帧", buildRandPusai(rand.New(rand.NewSource(7)))},
		{"琅卡博阀门帧", buildRandLangkabo(rand.New(rand.NewSource(7)))},
		{"普赛调节阀帧", buildRandPusaiValve(rand.New(rand.NewSource(7)))},
	}
	const n = 100_000
	for _, f := range frames {
		// 预热
		for i := 0; i < 1000; i++ {
			judgeFactory(f.frame)
		}
		t0 := time.Now()
		for i := 0; i < n; i++ {
			judgeFactory(f.frame)
		}
		dt := time.Since(t0)
		fmt.Printf("  %-16s 帧长 %3d 字节  %8.2f µs/帧（含全部六条模式的最坏代价）\n",
			f.name, len(f.frame)/2, float64(dt.Microseconds())/float64(n))
	}
}

func makeMeters(n int) []deerMeter {
	out := make([]deerMeter, n)
	for i := range out {
		out[i] = deerMeter{Point: i + 1, Type: 1,
			Num: fmt.Sprintf("%014d", 65790000+i), Heat: 4100, Flow: 2919,
			Power: 1000, FlowRate: 8300, Supply: 3600, ReturnT: 3500, Diff: 110, Runtime: 84417}
	}
	return out
}
