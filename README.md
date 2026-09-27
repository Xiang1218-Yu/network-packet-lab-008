# Network Packet Lab · 网络协议数据包可视化实验室

项目 10：一个用于学习和演示网络协议解析过程的可视化实验室。当前版本聚焦模拟 HTTP / TCP 数据包，提供输入、场景选择、协议层级字段树、十六进制数据、解析时间线，以及可供 React 管理界面调用的 Node.js API。

## 技术栈

- **前端**：React 18、Vite、TypeScript
- **后端**：Node.js、Express、TypeScript
- **工程**：前后端共享 `shared/types.ts` 类型，根目录统一管理脚本

## 目录结构

```text
network-packet-lab/
├── client/
│   ├── index.html
│   └── src/
│       ├── App.tsx
│       ├── main.tsx
│       └── styles.css
├── server/
│   └── index.ts
├── shared/
│   └── types.ts
├── package.json
├── tsconfig.json
├── tsconfig.server.json
├── vite.config.ts
└── .gitignore
```

## 功能

1. **模拟数据选择**：在 HTTP / TCP 协议之间切换，并选择请求、响应或 TCP 握手场景。
2. **数据包输入**：编辑原始 HTTP 文本或 TCP 模拟摘要，点击“解析数据包”重新生成可视化结果。
3. **协议字段树**：HTTP 展示起始行、Header、Payload；TCP 展示 Ethernet、IPv4、TCP 和 Payload 层级，并支持折叠。
4. **十六进制视图**：以 offset、hex bytes、ASCII 三列展示当前 payload 的 UTF-8 字节。
5. **传输时间线**：展示抓包、解析、传输层解码和结构化输出等阶段。
6. **TCP 流重建面板**：从捕获会话中勾选多个 TCP 段，服务端按连接与方向拆分后重建逻辑字节流——按到达顺序识别重传、重复段、部分重叠与缺口，按序号空间展示每段的流范围、字节流地图与 ACK 覆盖进度，并处理乱序输入、空选择、混合连接与序号回绕。
7. **解析 API / 模拟数据 API**：Express 服务提供 `/api/parse`、`/api/simulate`、`/api/packets`、`/api/tcp/session`、`/api/tcp/reassemble` 和 `/api/health`。

## 启动方式

当前只完整落盘项目文件，**没有安装依赖**。准备运行时，在本目录执行：

```bash
npm install
```

然后打开两个终端：

```bash
# 终端 1：启动 API 服务（默认 3001）
npm run dev:server

# 终端 2：启动 Vite 管理界面（默认 5173）
npm run dev:client
```

浏览器访问 `http://localhost:5173`。如需更换 API 地址，可设置 `VITE_API_BASE`，例如：

```bash
VITE_API_BASE=http://localhost:3001 npm run dev:client
```

生产构建：

```bash
npm run build
npm start
```

> `npm start` 会启动编译后的 API 服务；前端静态产物位于 `dist/client`，可交给任意静态服务器托管。

## API 示例

### 获取模拟数据

```bash
curl 'http://localhost:3001/api/simulate?protocol=HTTP&scenario=request'
curl 'http://localhost:3001/api/simulate?protocol=TCP&scenario=handshake'
```

### 解析输入数据包

```bash
curl -X POST 'http://localhost:3001/api/parse' \
  -H 'Content-Type: application/json' \
  -d '{"protocol":"HTTP","scenario":"request","raw":"GET /health HTTP/1.1\\r\\nHost: lab.local\\r\\n\\r\\n"}'
```

### 获取某协议的全部示例

```bash
curl 'http://localhost:3001/api/packets?protocol=TCP'
```

### 获取 TCP 捕获会话（流重建教学样例）

```bash
# scenario: textbook（有序）/ lossy（丢包重传）/ wrap（序号回绕）/ mixed（混合连接）
curl 'http://localhost:3001/api/tcp/session?scenario=lossy'
```

### 重建 TCP 字节流

```bash
curl -X POST 'http://localhost:3001/api/tcp/reassemble' \
  -H 'Content-Type: application/json' \
  -d '{"segments":[
    {"source":"10.0.0.24:51842","destination":"10.0.0.8:443","seq":1601,"ack":5001,"flags":["ACK","PSH"],"payloadLength":300,"capturedAt":"00:00:02.125"},
    {"source":"10.0.0.24:51842","destination":"10.0.0.8:443","seq":1001,"ack":5001,"flags":["ACK","PSH"],"payloadLength":300,"capturedAt":"00:00:02.120"}
  ]}'
```

返回按连接 / 方向拆分的关系数据：每段的流范围 `[rangeStart, rangeEnd)`、状态（按序 / 乱序到达 / 完整重传 / 重复段 / 部分重叠 / 控制段）、缺口与重叠区、方向切换次数、ACK 覆盖进度，以及混合连接、序号回绕等警告。空选择或非法序号会返回 `400` 与中文错误说明。

## 说明

本项目是教学用模拟器，不执行真实网卡抓包，也不声称校验真实 TCP 校验和。十六进制内容由当前输入字符串的 UTF-8 字节生成，字段解析为面向演示的轻量级解析结果。
