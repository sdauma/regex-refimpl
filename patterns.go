package main

import (
	"fmt"
	"regexp"
)

// 协议特征模式（论文表 1）：每条正则同时承担协议识别与字段抽取，
// 字符类为严格十六进制 [0-9A-F]，全部在包初始化时编译一次，
// 运行期不存在逐帧编译开销。
var (
	patternDEBAO = regexp.MustCompile(
		`^68(?P<len1>[0-9A-F]{2})(?P<len2>[0-9A-F]{2})(?P<len1>[0-9A-F]{2})(?P<len2>[0-9A-F]{2})68(?P<ctrl>[0-9A-F]{2})(?P<addr>[0-9A-F]{10})(?P<di>[0-9A-F]{2})(?P<seq>[0-9A-F]{2})[0-9A-F]+16$`)

	patternPUSAI = regexp.MustCompile(
		`^7E(?P<ctrl>[0-9A-F]{2})(?P<body>[0-9A-F]+)7E$`)

	patternDEER = regexp.MustCompile(
		`^EB90EB90EB90(?P<len>[0-9A-F]{2})(?P<cmd>[0-9A-F]{2})(?P<cid>[0-9A-F]{4})(?P<payload>[0-9A-F]*)(?P<cs>[0-9A-F]{2})$`)

	patternLANGKABO = regexp.MustCompile(
		`^68(?P<len1>[0-9A-F]{2})(?P<len2>[0-9A-F]{2})59(?P<random>[0-9A-F]{4})(?P<ctrl>[0-9A-F]{2})(?P<addr>[0-9A-F]{8})(?P<factory>[0-9A-F]{6})[0-9A-F]*(?P<cs>[0-9A-F]{2})16$`)

	patternBOSIDA = regexp.MustCompile(
		`^(?P<pre>[0-9CEF]{2,8})6850(?P<addr>[0-9A-F]{14})(?P<cmd>[0-9A-F]{2})(?P<len>[0-9A-F]{2})(?P<data>[0-9A-F]+)(?P<cs>[0-9A-F]{2})16$`)

	patternPUSAIVALVE = regexp.MustCompile(
		`^FEFE7E(?P<ctrl>[0-9A-F]{2})(?P<addr>[0-9A-F]{12})(?P<seq>[0-9A-F]{2})[0-9A-F]+7E$`)
)

// 协议特征编码与匹配次序：按序遍历，先命中先返回，仅为实现层面的确定性 tie-breaker。
// 各模式的唯一性由定界符、长度域、特定字节串与正则结构等多重条件在协议分析阶段保证，
// 正常建模下各模式互不交叉命中；该遍历次序不应被依赖为歧义消解机制
// （如普赛集抄器 30 先于普赛温控阀 400 仅为稳定返回顺序，非消歧规则）。
type protocolPattern struct {
	code    int
	name    string
	pattern *regexp.Regexp
}

var protocolTable = []protocolPattern{
	{40, "德宝集抄器", patternDEBAO},
	{30, "普赛集抄器", patternPUSAI},
	{20, "德尔集抄器", patternDEER},
	{200, "琅卡博温控阀", patternLANGKABO},
	{300, "博思达温控阀", patternBOSIDA},
	{400, "普赛温控阀", patternPUSAIVALVE},
}

func patternByCode(code int) *protocolPattern {
	for i := range protocolTable {
		if protocolTable[i].code == code {
			return &protocolTable[i]
		}
	}
	return nil
}

// judgeFactory 对单帧十六进制串按序匹配协议特征模式，
// 返回首个命中协议的特征编码与命名捕获组。
func judgeFactory(frame string) (int, string, map[string]string, bool) {
	for _, p := range protocolTable {
		if m := p.pattern.FindStringSubmatch(frame); m != nil {
			return p.code, p.name, subexpMap(p.pattern, m), true
		}
	}
	return 0, "", nil, false
}

func subexpMap(re *regexp.Regexp, m []string) map[string]string {
	out := make(map[string]string, len(m)-1)
	for i, name := range re.SubexpNames() {
		if i > 0 && name != "" {
			out[name] = m[i]
		}
	}
	return out
}

// identifyFrame 完整识别路径：结构层（特征模式按序匹配）之后
// 叠加语义层（长度一致性与校验和），二者共同构成两道防线；
// 结构层命中但语义校验失败的帧整体拒收。
func identifyFrame(frame string) (int, string, map[string]string, bool) {
	code, name, sub, ok := judgeFactory(frame)
	if !ok {
		return 0, "", nil, false
	}
	if checked, pass := semanticValidate(code, sub, frame); checked && !pass {
		return 0, "", nil, false
	}
	return code, name, sub, true
}

// semanticValidate 语义层校验：正则命中后的长度一致性与校验和验证，
// 与结构层（特征模式）共同构成两道防线。
// checked=false 表示该协议族无长度/校验域可依（识别级仅结构层）。
func semanticValidate(code int, sub map[string]string, frame string) (checked, ok bool) {
	switch code {
	case 20: // 德尔：LEN 一致性 + 累加和
		body := sub["cmd"] + sub["cid"] + sub["payload"]
		l := len(body)/2 + 1
		if pad2(fmt.Sprintf("%02X", l)) != sub["len"] {
			return true, false
		}
		prefix := deerHeader + sub["len"]
		return true, checksum8(prefix[6:]+body) == sub["cs"]
	case 300: // 博思达：累加和
		core := "6850" + sub["addr"] + sub["cmd"] + sub["len"] + sub["data"]
		return true, checksum8(core) == sub["cs"]
	case 40: // 德宝：双长度域一致 + 帧长一致
		if sub["len1"] != sub["len2"] {
			return true, false
		}
		return true, int(leToUint(sub["len1"])) == len(frame)/2-4
	}
	return false, true
}