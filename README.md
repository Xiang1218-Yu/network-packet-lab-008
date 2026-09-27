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
│       ├── TcpStreamPanel.tsx
│       ├── main.tsx
│       └── styles.css
├── server/
│   ├── index.ts
│   └── tcp-stream.ts
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
6. **TCP 流重建**：从捕获会话中勾选多个 TCP 段，服务端按连接分组、分离双向字节流，以 SYN（ISN+1）或推断值为基准序号，按 RFC 1982 模 2^32 算术把每个段映射到逻辑字节流区间，识别重传、缺口、重叠、重复 ACK 与方向切换，并解读每个 ACK 是否覆盖对端已发送的数据；前端提供字节流区间图、流内排序表、事件流，以及混用连接、空选择、序号回绕的提示。
7. **解析 API / 模拟数据 API**：Express 服务提供 `/api/parse`、`/api/simulate`、`/api/packets`、`/api/capture-session`、`/api/tcp-stream/reassemble` 和 `/api/health`。

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

### 获取捕获会话（TCP 流重建）

```bash
# scenario: standard | loss | wraparound | mixed
curl 'http://localhost:3001/api/capture-session?scenario=loss'
```

### 重建 TCP 流

```bash
curl -X POST 'http://localhost:3001/api/tcp-stream/reassemble' \
  -H 'Content-Type: application/json' \
  -d '{"segments":[{"id":"seg-01","source":"10.0.0.24:51842","destination":"10.0.0.8:443","seq":5000,"ack":0,"flags":["SYN"],"payloadLength":0}]}'
```

响应包含：连接端点与方向划分、每个方向的基准序号与覆盖统计、每个段在逻辑字节流中的 `[start, end)` 区间与异常标记（重传 / 缺口 / 重叠 / 重复 ACK / 回绕可疑）、ACK 覆盖解读、按捕获顺序排列的事件流，以及混用连接被排除的段与告警。

## 说明

本项目是教学用模拟器，不执行真实网卡抓包，也不声称校验真实 TCP 校验和。十六进制内容由当前输入字符串的 UTF-8 字节生成，字段解析为面向演示的轻量级解析结果。
