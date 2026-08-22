package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// ---------- 博思达温控阀 MBUS 协议 ----------
//
// 帧结构：[FE 前导] 68 50 阀门地址(7B) CMD LEN DATA CS 16
// LEN 为 DATA 字节数；CS 为 68 起至 DATA 末字节的累加和低 8 位。

const (
	bosidaPreamble  = "FEFEFEFE"
	bosidaCmdReport = "81" // 阀门状态上报（同时充当下行读取应答）
	bosidaCmdCtrl   = "16" // 开度设置（下行）
	bosidaCmdAck    = "96" // 阀门对开度设置的应答（上行）
)

func bosidaFrame(pre, addr, cmd, data string) string {
	core := "6850" + addr + cmd + pad2(fmt.Sprintf("%02X", len(data)/2)) + data
	return pre + core + checksum8(core) + "16"
}

// bosidaControlCmd 生成开度设置命令（论文表 3）：
// FEFEFEFE + 68 50 阀门地址(7B) 16 04 A01700 开度 CS 16
func bosidaControlCmd(addr string, opening int) string {
	data := fmt.Sprintf("A01700%02X", opening)
	return bosidaFrame(bosidaPreamble, addr, bosidaCmdCtrl, data)
}

// bosidaReport 上报帧数据域（34 字节）的可解释字段。
// 前两路 16 位原始温度的厂家换算未在协议文本中明确，按原始值透传。
type bosidaReport struct {
	Addr     string
	T1       uint16
	T2       uint16
	Indoor   uint16 // 室内温度原始值
	Setpoint uint16 // 设定温度原始值
	AccMin   uint32 // 累计运行分钟
	AccHeat  uint32 // 累计热量原始值
	TimeBCD  string
	Ctrl     byte
	Mode     byte
	State    byte
	Opening  byte // 阀门开度，0–100
	Fault    byte
}

func bosidaBuildReport(r bosidaReport) string {
	data := "901F00" +
		u16le(r.T1) + u16le(r.T2) + u16le(r.Indoor) + u16le(r.Setpoint) +
		u32le(r.AccMin) + u32le(r.AccHeat) + "00000000" +
		r.TimeBCD +
		fmt.Sprintf("%02X%02X%02X%02X%02X", r.Ctrl, r.Mode, r.State, r.Opening, r.Fault)
	return bosidaFrame(bosidaPreamble, r.Addr, bosidaCmdReport, data)
}

func parseBosidaReport(addr, data string) bosidaReport {
	r := bosidaReport{Addr: addr}
	if len(data) < 68 {
		return r
	}
	r.T1 = uint16(leToUint(data[6:10]))
	r.T2 = uint16(leToUint(data[10:14]))
	r.Indoor = uint16(leToUint(data[14:18]))
	r.Setpoint = uint16(leToUint(data[18:22]))
	r.AccMin = uint32(leToUint(data[22:30]))
	r.AccHeat = uint32(leToUint(data[30:38]))
	r.TimeBCD = data[46:58]
	r.Ctrl = hexVal2(data[58:60])
	r.Mode = hexVal2(data[60:62])
	r.State = hexVal2(data[62:64])
	r.Opening = hexVal2(data[64:66])
	r.Fault = hexVal2(data[66:68])
	return r
}

// handleBOSIDA 处理博思达温控阀上行帧：注册 → 上报解析 / 应答路由
// （校验和已由识别路径的语义层完成，见 identifyFrame）
func handleBOSIDA(conn net.Conn, sub map[string]string, addr string) {
	switch sub["cmd"] {
	case bosidaCmdReport:
		r := parseBosidaReport(sub["addr"], sub["data"])
		registry.register("BSD-V-"+r.Addr, addr)
		log.Printf("[博思达] 温控阀 %s 在线：开度=%d%% 室内温度raw=%d 时间=%s", r.Addr, r.Opening, r.Indoor, r.TimeBCD)
		pendingRetry("BSD-V-" + r.Addr)
	case bosidaCmdAck:
		if c, ok := ackWaiters.Load(addr); ok {
			select {
			case c.(chan string) <- sub["addr"]:
			default:
			}
		}
	default:
		log.Printf("[博思达] 未处理命令 %s（来自 %s）", sub["cmd"], addr)
	}
}

// genericDeviceCode 为识别级协议（德宝/普赛/琅卡博/普赛阀）推导设备编码
func genericDeviceCode(code int, sub map[string]string) (string, bool) {
	switch code {
	case 40:
		return "DB-" + sub["addr"], true
	case 30:
		if len(sub["body"]) >= 14 {
			return "PSM-" + sub["body"][:14], true
		}
	case 200:
		return "LKB-" + sub["addr"], true
	case 400:
		return "PSV-" + sub["addr"], true
	}
	return "", false
}

func valveAddrFromCode(code string) string {
	return strings.TrimPrefix(code, "BSD-V-")
}