package main

import (
	"fmt"
	"log"
	"net"
)

// ---------- 德尔 EB90 协议 ----------
//
// 帧结构：EB90EB90EB90 + LEN(1B) + CMD(1B) + 集抄器标识(2B) + 载荷 + CS(1B)
// LEN 覆盖 CMD..CS（含）；CS 为 LEN 起至载荷末字节的累加和低 8 位。

const (
	deerHeader  = "EB90EB90EB90"
	deerCmdData = "01" // 集抄器数据读取（要数）上报帧（协议文档功能码 01）
	deerCmdBeat = "9F" // 集抄器心跳 / ID 读取帧（协议文档功能码 9F）
	deerCmdAck  = "9F" // 平台对心跳的应答帧（下行，命令码与心跳相同，错误字 00=成功）
)

func deerFrame(cmd, cid, payload string) string {
	body := cmd + cid + payload
	l := len(body)/2 + 1
	prefix := deerHeader + pad2(fmt.Sprintf("%02X", l))
	return prefix + body + checksum8(prefix[6:]+body)
}

func deerHeartbeat(cid string) string {
	return deerFrame(deerCmdBeat, cid, "")
}

// deerMeter 一块热量表的读数（值均为原始整数，物理量 = 原始值 / 精度）
type deerMeter struct {
	Point    int
	Type     int
	Num      string // 表号，7 字节小端 BCD 的原始十六进制形式
	Heat     uint32 // 累计热量，0.01 kWh
	Flow     uint32 // 累计流量，0.01 m³
	Power    uint32 // 热功率，0.01 kW
	FlowRate uint32 // 流速，0.01 L/h
	Supply   uint32 // 进水温度，0.01 ℃
	ReturnT  uint32 // 回水温度，0.01 ℃
	Diff     uint32 // 温度差，0.01 K
	Runtime  uint32 // 累计运行时间，1 h
	Fault    uint32 // 故障代码
}

// 各数据域的单位码（取自真实样例帧）
var deerUnits = []string{"06", "14", "2D", "3B", "5B", "5F", "62", "22", "00"}

func deerRecord(m deerMeter) string {
	s := fmt.Sprintf("%02X%02X%s", m.Point, m.Type, m.Num)
	vals := []uint32{m.Heat, m.Flow, m.Power, m.FlowRate, m.Supply, m.ReturnT, m.Diff, m.Runtime, m.Fault}
	for i, v := range vals {
		s += u32le(v) + deerUnits[i]
	}
	return s
}

func deerData(cid string, meters []deerMeter, timeBCD string) string {
	payload := timeBCD + "FFFFFFFFFFFFFFFF"
	for _, m := range meters {
		payload += deerRecord(m)
	}
	return deerFrame(deerCmdData, cid, payload)
}

type deerMeterReading struct {
	Point   int
	Num     string
	Heat    float64
	Flow    float64
	Power   float64
	Rate    float64
	Supply  float64
	ReturnT float64
	Diff    float64
	Runtime uint32
	Fault   uint32
}

// parseDeerPayload 解析数据帧载荷：时间(6B=12hex) + 分隔符(8B FF=16hex) + N 条 54 字节(108hex)记录
// 记录起始于 payload 偏移 28 hex（12+16），每条记录内各数值域为 4 字节(8hex)小端整数。
func parseDeerPayload(p string) []deerMeterReading {
	if len(p) < 28 {
		return nil
	}
	recs := p[28:]
	out := []deerMeterReading{}
	for len(recs) >= 108 {
		r := recs[:108]
		field := func(k int) uint32 { return uint32(leToUint(r[18+10*k : 26+10*k])) }
		out = append(out, deerMeterReading{
			Point:   int(leToUint(r[0:2])),
			Num:     bytesToHex(reverseBytes(hexToBytes(r[4:18]))),
			Heat:    float64(field(0)) / 100,
			Flow:    float64(field(1)) / 100,
			Power:   float64(field(2)) / 100,
			Rate:    float64(field(3)) / 100,
			Supply:  float64(field(4)) / 100,
			ReturnT: float64(field(5)) / 100,
			Diff:    float64(field(6)) / 100,
			Runtime: field(7),
			Fault:   field(8),
		})
		recs = recs[108:]
	}
	return out
}

// handleDEER 处理德尔集抄器上行帧：心跳/数据帧均触发地址注册
func handleDEER(conn net.Conn, sub map[string]string, addr string) {
	switch sub["cmd"] {
	case deerCmdBeat:
		registry.register("DEER-C-"+sub["cid"], addr)
		ack := deerFrame(deerCmdAck, sub["cid"], "00")
		if _, err := conn.Write(hexToBytes(ack)); err != nil {
			log.Printf("[德尔] 心跳应答失败 %s: %v", addr, err)
		}
	case deerCmdData:
		registry.register("DEER-C-"+sub["cid"], addr)
		readings := parseDeerPayload(sub["payload"])
		for _, m := range readings {
			registry.register("DEER-M-"+m.Num, addr)
		}
		if len(readings) > 0 {
			r := readings[0]
			log.Printf("[德尔] cid=%s %d 块表，首表 %s：热量=%.2f kWh 流量=%.2f m³ 进水=%.2f℃ 回水=%.2f℃ 温差=%.2f K",
				sub["cid"], len(readings), r.Num, r.Heat, r.Flow, r.Supply, r.ReturnT, r.Diff)
		}
	default:
		// 未模拟的命令：热量表集抄器的校时(89)/读时间(93)/各类设置，以及 NB 温度仪
		// 的历史数据(02/22)/实时数据(89)/温度补偿(84) 等均未纳入实验覆盖面。
		log.Printf("[德尔] 未处理命令 %s（来自 %s，该命令或属未模拟设备类型）", sub["cmd"], addr)
	}
}