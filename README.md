# regex-refimpl

基于正则表达式匹配的异构终端单点集控参考实现（论文《基于正则表达式匹配的异构终端单点集控方法》配套代码）。

本实现以声明式接入范式（协议即字符串—正则即协议）与链路主动注册反向控制机制，演示单端口并发监听下对多厂商、多协议终端的解析与反向控制。

## 环境要求

- Go 1.25（或兼容版本）
- 操作系统：Windows / Linux / macOS

## 构建

```sh
go build -o regex-refimpl.exe .        # Windows
# 或
go build -o regex-refimpl .            # Linux / macOS
```

## 运行

程序以子命令方式调用，常用命令如下：

```sh
# 启动单点集控服务端（单端口监听，地址注册表持久化到 registry.json）
regex-refimpl server    [-port 9047] [-rpc 3388] [-registry registry.json] [-stale 90s]

# 模拟 deer 协议终端（自动建链、断后重连）
regex-refimpl simdeer   [-server 127.0.0.1:9047] [-bind 127.0.0.2] [-cid 0A00] \
                        [-heartbeat 15s] [-report 45s] [-rebindAfter N] [-duration 5m]

# 模拟 valve 协议终端（带变 IP 场景）
regex-refimpl simvalve  [-server 127.0.0.1:9047] [-bind 127.0.0.3] [-addr 19271234001111] \
                        [-heartbeat 15s] [-rebindAfter N] [-duration 5m]

# 发起反向控制指令（变 IP 下亦可正确投递）
regex-refimpl control   -device BSD-V-19271234001111 -opening 50 [-rpc http://127.0.0.1:3388]

# 运行实验（准确性 / 变 IP 恢复 / 性能基准 / 跨协议误匹配）
regex-refimpl experiment accuracy|ipchange|bench|xmatch
```

## 复现论文实验

配套的实验输出数据位于本目录（`regex-refimpl`）：

- `accuracy_result.txt`：匹配准确性实验结果（合规帧识别与解析、畸形帧拒收），对应正文 `expAccuracy`。
- `bench_result.txt`：性能基准结果（单帧多模式匹配时延，对应正文引用路径 `regex-refimpl/bench_result.txt`）。
- `ipchange_result.txt`：变 IP 反向控制恢复实验结果，对应正文 `expIPChange`。
- `xmatch_result.txt`：跨协议误匹配矩阵（各协议帧仅被所属模式命中），对应正文 `expXMatch`。

准确性实验（`experiment accuracy`，参考实现记为 `expAccuracy`）在每次运行时由程序构造并校验 1204 条合规帧与 90 条畸形帧，不另存静态数据文件；其余三项实验的输出如上所列。论文第 4 章的准确性、变 IP 反向控制、性能论据、跨协议误匹配等数据均由上述命令与数据文件对应产生。

## 目录说明

| 文件 | 说明 |
| --- | --- |
| `main.go` | 入口与子命令分发 |
| `server.go` | 单端口并发监听、连接对象映射与地址注册表 |
| `patterns.go` | 各厂商协议的正则模式声明 |
| `frames.go` | 合规帧与畸形帧构造 |
| `registry.go` | 地址注册表（第一级寻址） |
| `control.go` | 反向控制指令下发 |
| `sim.go` | 终端模拟器（建链/心跳/重连） |
| `deer.go` / `bosida.go` | 具体厂商协议解析 |
| `experiment.go` | 实验编排（accuracy / ipchange / bench） |
