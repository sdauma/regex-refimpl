package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---------- 十六进制与字节序工具 ----------

func bytesToHex(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func hexVal2(s string) byte {
	v, err := strconv.ParseUint(s, 16, 8)
	if err != nil {
		return 0
	}
	return byte(v)
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

// leToUint 将小端（低字节在前）十六进制段还原为无符号整数
func leToUint(s string) uint64 {
	var v uint64
	for _, b := range reverseBytes(hexToBytes(s)) {
		v = v<<8 | uint64(b)
	}
	return v
}

func u16le(v uint16) string {
	return bytesToHex([]byte{byte(v), byte(v >> 8)})
}

func u32le(v uint32) string {
	return bytesToHex([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}

func checksum8(s string) string {
	sum := 0
	for _, b := range hexToBytes(s) {
		sum += int(b)
	}
	return pad2(fmt.Sprintf("%02X", sum&0xFF))
}

func pad2(s string) string {
	for len(s) < 2 {
		s = "0" + s
	}
	return strings.ToUpper(s)
}

// bcdNow 生成 6 字节 BCD 时间戳（日 月 年 时 分 秒，与 EB90 样例一致）
func bcdNow() string {
	t := time.Now()
	return fmt.Sprintf("%02d%02d%02d%02d%02d%02d",
		t.Day(), int(t.Month()), t.Year()%100, t.Hour(), t.Minute(), t.Second())
}

func trunc(s string) string {
	if len(s) > 48 {
		return s[:48] + "..."
	}
	return s
}

// ---------- TCP 流帧定界 ----------
//
// TCP 是字节流，协议帧会以粘包或半帧形态到达。定界策略：
// 在偶数字节边界上寻找候选帧起点（EB90EB90EB90 / 68 族 / 7E 族 / FEFE 前导），
// 按各帧族的长度启发式或帧尾枚举截取候选帧，再以协议特征模式验证；
// 验证失败则滑动一个字节重新定界。
type frameScanner struct {
	buf []byte
}

func (s *frameScanner) write(p []byte) { s.buf = append(s.buf, p...) }

func (s *frameScanner) drop(n int) {
	if n >= len(s.buf) {
		s.buf = s.buf[:0]
		return
	}
	s.buf = s.buf[n:]
}

func (s *frameScanner) next() (string, bool) {
	for {
		h := bytesToHex(s.buf)
		if len(h) < 16 {
			return "", false
		}
		start, kind := scanStart(h)
		if start < 0 {
			// 缓冲区内无已知帧头：若持续膨胀则丢弃，否则等待后续字节
			if len(s.buf) > 2048 {
				s.drop(len(s.buf) - 16)
			}
			return "", false
		}
		if start > 0 {
			s.drop(start / 2)
			continue
		}
		var (
			cand string
			wait bool
		)
		switch kind {
		case 1: // EB90 族：帧长 = 3 帧头 + 1 长度 + LEN（LEN 覆盖 CMD..CS 含）
			need := (4 + int(hexVal2(h[6:8]))) * 2
			if len(h) < need {
				wait = true
			} else {
				cand = h[:need]
			}
		case 2: // 68 族（含 FE 前导的博思达/琅卡博）：枚举偶数边界上的帧尾 16
			cand, wait = scanTail(h, "16", 20)
		case 3: // 7E 族：枚举偶数边界上的帧尾 7E
			cand, wait = scanTail(h, "7E", 18)
		}
		if wait {
			return "", false
		}
		if cand != "" {
			if _, _, _, ok := identifyFrame(cand); ok {
				s.drop(len(cand) / 2)
				return cand, true
			}
		}
		s.drop(1) // 候选不成立：滑动一个字节重新定界
	}
}

// scanStart 返回首个已知帧族起点的字符偏移与族编号
func scanStart(h string) (int, int) {
	for i := 0; i+2 <= len(h); i += 2 {
		switch {
		case strings.HasPrefix(h[i:], "EB90EB90EB90"):
			return i, 1
		case strings.HasPrefix(h[i:], "FEFE7E"):
			return i, 3
		case strings.HasPrefix(h[i:], "FEFE"):
			// FE 前导的 68 族（博思达）
			return i, 2
		case strings.HasPrefix(h[i:], "68"):
			return i, 2
		case strings.HasPrefix(h[i:], "7E"):
			return i, 3
		case isPreambleByte(h[i:i+2]) && follow68(h, i+2):
			return i, 2
		}
	}
	return -1, 0
}

// isPreambleByte 判断是否 68 族的唤醒前导字节（FE/0C/0E/0F）
func isPreambleByte(s string) bool {
	switch s {
	case "FE", "0C", "0E", "0F":
		return true
	}
	return false
}

func follow68(h string, i int) bool {
	return i+2 <= len(h) && h[i:i+2] == "68"
}

// scanTail 在 minChars 之后枚举帧尾位置，返回首个通过识别路径
// （结构层+语义层）验证的候选帧——数据域内出现的伪帧尾会因
// 语义校验失败被跳过，避免真帧在数据中间被误切
func scanTail(h, tail string, minChars int) (string, bool) {
	found := false
	for k := minChars; k <= len(h); k += 2 {
		if h[k-2:k] == tail {
			found = true
			if _, _, _, ok := identifyFrame(h[:k]); ok {
				return h[:k], false
			}
		}
	}
	if !found {
		return "", true // 尚未见帧尾，等待更多字节
	}
	return "", false // 见过帧尾但均未通过验证，由调用方滑动一个字节
}
