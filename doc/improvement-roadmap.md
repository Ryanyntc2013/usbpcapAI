# USBPcapMCP 下一阶段改进路线图

> 编写日期：2026-07-05  
> 当前版本：v0.1.0（已修复 2 个关键 bug）

---

## 一、当前架构

```
VS Code ← stdio/jsonrpc → USBPcapMCP.exe ← named pipe → USBPcapService.exe → USBPcapCap.exe
           (Go, MCP 协议)         (ipc.Call, 30s超时)    (Windows 服务)       (C, 驱动层抓包)
```

**MCP Server 当前提供的 10 个工具：**

| 工具 | 类型 | 状态 |
|------|------|------|
| `usbpcap_list_interfaces` | 发现 | ✅ |
| `usbpcap_list_devices` | 发现 | ✅ |
| `usbpcap_capture_once` | 同步抓包 | ✅ 有问题见 P0-2 |
| `usbpcap_start_capture` | 异步抓包 | ✅ |
| `usbpcap_get_capture_task` | 查询 | ✅ |
| `usbpcap_list_capture_tasks` | 查询 | ✅ |
| `usbpcap_stop_capture` | 控制 | ✅ |
| `usbpcap_capture_status` | 状态 | ✅ |
| `usbpcap_get_config` | 配置 | ✅ |
| `usbpcap_help` | 帮助 | ✅ |

---

## 二、已修复的 Bug（本阶段完成）

### Bug 1: VID/PID 过滤导致抓包失败 🔴

- **文件**: `USBPcapAI/internal/usbpcapcmd/runner.go:89`
- **现象**: 传 `vendorId=0x1a86` 时 `start_capture` 返回 `exit status 0xffffffff`
- **根因**: VID/PID 非空时不加 `-A`，USBPcapCap 中 VID/PID 仅 set `app_filter` 不填充 `address_list`，capture_thread sanity check 失败
- **修复**: 只要不是 `captureNewDevices` 都加 `-A`（1 行改动）

### Bug 2: Summary 统计全错 🔴

- **文件**: `USBPcapAI/internal/pcap/summary.go` + `summary_test.go`
- **现象**: `deviceDistribution={"0x02":74}` 实际应为 `{"0x10":66,"0x11":8}`
- **根因**: USBPcap 头字段偏移量错误。Device (offset 19)、Endpoint (offset 21)、Transfer (offset 22) 被读成了 Bus (offset 17)、Device[0] (offset 19)、Device[1] (offset 20)
- **影响**: deviceDistribution / endpointDistribution / transferTypes 三个统计全错
- **修复**: 修正 3 处偏移量，同步更新测试用例

---

## 三、下一阶段改进建议

### 🔴 P0 — 影响核心可用性

#### P0-1: 空闲设备抓包 → 应返回 `DEVICE_IDLE` 而非 `completed` 含 0 packet

**现状**：`start_capture` + `get_capture_task` 返回 `completed` 但 `packetCount=0, sizeBytes=24`（仅 pcap 头）。无法区分"设备静默"和"USBPcap 故障"。

**期望行为**：
- 若 `matchedDevices` 非空但 `packetCount=0` → 返回 `status: "idle"`，message 包含 "设备静默无流量，请触发采集或重启 GUI"
- 若 USBPcapCap 返回 `NO_MATCHED_DEVICE` → 返回 `status: "no_device"`
- 若未提供 VID/PID、只是整接口抓包且 `packetCount=0` → 不应贸然判断为 `no_device`，应返回 `idle` 或 `empty_capture`

**实现位置**：`internal/service/server.go` `finalizeTask()` 方法

```go
if summary.PacketCount == 0 && len(task.task.MatchedDevices) > 0 {
    task.task.Status = "idle"
    task.task.Message = "Device(s) found but no traffic captured. Device may be idle."
    task.task.Hint = "Trigger device activity (e.g. GUI capture) or restart the device."
}
```

**实现注意**：Go `usbpcapcmd.Runner` 需要保留 C 侧 JSON 中的 `errorCode/message/hint`，不要把 `NO_MATCHED_DEVICE` 丢成普通 `error` 字符串，否则 service 层无法可靠映射 `no_device`。

#### P0-2: `capture_once` 长任务体验不佳，需明确超时边界

**现状修订**：`ipc.Call` 中的 30s context 当前主要用于连接 named pipe；服务端 `captureOnce` 会等待 `task.done`，不应简单判断为“抓包 30s 必然超时”。如果实际出现长采集失败，需要区分是 MCP 客户端超时、外层工具超时、pipe 读写超时，还是 USBPcapCMD 自身问题。

**期望**：

- 对短抓包：`capture_once` 继续可用。
- 对长抓包：AI 优先使用 `start_capture` + `wait_capture_task`。
- 如果实现 `CallWithTimeout`，应同时覆盖 pipe 连接、读写 deadline 和 MCP 层等待，而不是只包住 `DialPipeContext()`。
- `capture_once` 响应中应提示长任务推荐的下一步：`start_capture` + `wait_capture_task`。

**实现位置**：`internal/ipc/client.go` 或 MCP `callTool` 函数

```go
func CallWithTimeout(req Request, timeout time.Duration) (Response, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    // ...
}
```

**建议**：不要只依赖 `capture_once` 解决 AI 效率问题；更推荐新增 `wait_capture_task` 和 `smart_capture`。

---

### 🟡 P1 — 提升效率

#### P1-0: AI Agent 友好性总原则

**目标**：让中低等 AI 模型也能稳定抓到数据、少犯错、少走弯路。

当前工具偏底层，AI 需要自行完成：列接口 → 列设备 → 判断接口 → 抓包 → 轮询任务 → 判断空包 → 再分析。弱模型容易犯以下错误：

- 忘记先找设备或选错 interface
- 把 `USBPcap2`、`81`、`1a86` 等非规范参数直接传入
- `start_capture` 后忘记查询任务
- 遇到 0 packet 时误判为抓包成功
- 设置 endpoint/transferType 但忘记 `appFilter=true`
- 空包后盲目重试相同参数

**改进方向**：

1. 增加高阶工具，把多步流程封装成一个确定性流程。
2. 所有结果返回结构化 `status`、`hint`、`nextAction`。
3. 服务端自动规范化常见参数，降低模型输入错误概率。
4. 对失败/空包场景给出诊断，而不是只返回自然语言错误。
5. 优先提供显式 `wait` 工具，MCP notifications 作为增强能力，不作为唯一机制。

---

#### P1-1: 新增 `usbpcap_probe_device` 工具

**动机**：当前 `list_devices` 需手动指定 interface。ATK-Logic 场景下需要自动跨接口探测。

**接口定义**：

```json
{
  "name": "usbpcap_probe_device",
  "description": "自动扫描所有 USBPcap 接口，查找匹配 VID/PID 的设备，返回接口和设备地址。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "vendorId":  {"type": "string", "description": "例如 0x1a86"},
      "productId": {"type": "string", "description": "例如 0xffcc"}
    }
  }
}
```

**实现思路**：
1. 调用 `listInterfaces` → 对所有接口调用 `listDevices`
2. 过滤匹配 VID/PID 的设备
3. 返回 `{interface, address, vid, pid, description}`

**实现位置**：`internal/service/server.go` 新增 `"probeDevice"` action

**AI 执行规则**：

- 如果用户只给了 VID/PID，不知道 interface，AI 必须先调用 `usbpcap_probe_device`。
- 如果返回 1 个设备，后续抓包使用返回的 `interface`。
- 如果返回多个设备，工具必须返回 `status: "ambiguous_device"` 和候选列表，AI 不应自行猜测。
- 如果返回 0 个设备，工具必须返回 `status: "no_device"`，AI 应提示用户确认设备连接。

#### P1-2: 新增 `usbpcap_wait_capture_task` 工具

**动机**：弱模型在 `start_capture` 后容易忘记轮询或重复调用无关工具。显式等待工具比依赖 MCP notifications 更稳定。

**接口定义**：

```json
{
  "name": "usbpcap_wait_capture_task",
  "description": "等待异步抓包任务完成，返回最终任务状态、pcap 路径、summary 和下一步建议。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "taskId": {"type": "string"},
      "timeoutSeconds": {"type": "integer", "default": 60}
    },
    "required": ["taskId"]
  }
}
```

**行为**：

1. 查找 taskId。
2. 若任务仍在运行，则阻塞等待到完成或超时。
3. 完成后返回完整 task、summary、pcapPath、`nextAction`。
4. 如果等待超时，返回 `status: "timeout"`，但不取消抓包任务。

**返回示例**：

```json
{
  "ok": true,
  "status": "completed",
  "taskId": "capture-12",
  "pcapPath": "E:\\test\\usbpcap\\output\\release\\captures\\x.pcap",
  "summary": {"packetCount": 128},
  "nextAction": {
    "tool": "usbpcap_analyze",
    "arguments": {"pcapPath": "E:\\test\\usbpcap\\output\\release\\captures\\x.pcap"}
  }
}
```

#### P1-3: 新增 `usbpcap_smart_capture` 高阶工具

**动机**：让 AI 用一个工具完成“探测 → 选择接口 → 抓包 → 等待 → 摘要 → 建议下一步”。这是提升抓包成功率的核心。

**接口定义**：

```json
{
  "name": "usbpcap_smart_capture",
  "description": "自动探测设备、选择接口、抓包、等待完成并返回摘要和下一步建议。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "interface": {"type": "string"},
      "vendorId": {"type": "string", "description": "例如 0x1a86，也允许 1a86"},
      "productId": {"type": "string", "description": "例如 0xffcc，也允许 ffcc"},
      "endpoint": {"type": "string", "description": "例如 0x81，也允许 81"},
      "transferType": {"type": "string", "enum": ["control", "bulk", "interrupt", "isochronous", "unknown"]},
      "durationSeconds": {"type": "integer", "default": 10},
      "analyze": {"type": "boolean", "default": true},
      "storeMode": {"type": "string", "enum": ["immediate", "on-match"], "default": "immediate"}
    }
  }
}
```

**服务端流程**：

1. 规范化参数：VID/PID、endpoint、interface。
2. 如果未传 interface 且有 VID/PID，自动执行 probe。
3. 如果唯一匹配，使用该 interface 抓包。
4. 如果多个匹配，返回 `ambiguous_device`。
5. 如果无匹配，返回 `no_device`。
6. 自动启动抓包并等待完成。
7. 若 `packetCount > 0`，返回 `completed`，并在 `analyze=true` 时返回基础分析结果。
8. 若 `packetCount == 0 && matchedDevices 非空`，返回 `idle`。
9. 若过滤过严，返回 `no_match` 或 `filter_too_strict` 建议。

**AI 执行规则**：

- 用户说“帮我抓某个 VID/PID 的包”时，优先调用 `usbpcap_smart_capture`。
- 用户不知道 endpoint 时，不要先加 endpoint 过滤；先让 smart capture 获取 endpoint 分布。
- 如果 smart capture 返回 `nextAction`，AI 应优先执行 `nextAction`，不要自行猜测。

#### P1-4: 新增 `usbpcap_diagnose_capture` 工具

**动机**：抓不到包时，弱模型容易重复同样错误。诊断工具应把失败原因结构化。

**接口定义**：

```json
{
  "name": "usbpcap_diagnose_capture",
  "description": "诊断为什么抓不到数据，并返回下一步建议。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "taskId": {"type": "string"},
      "vendorId": {"type": "string"},
      "productId": {"type": "string"}
    }
  }
}
```

**诊断枚举**：

| diagnosis | 含义 | 推荐动作 |
|-----------|------|----------|
| `NO_DEVICE` | 未发现匹配设备 | 提示用户插入/重连设备 |
| `DEVICE_IDLE` | 找到设备但无流量 | 提示用户触发设备动作，或延长抓包 |
| `WRONG_INTERFACE` | interface 与设备不匹配 | 重新 probe |
| `FILTER_TOO_STRICT` | endpoint/transferType 过滤过严 | 去掉 endpoint 过滤重抓 |
| `ENDPOINT_NO_TRAFFIC` | 指定 endpoint 没有流量 | 先 analyze 全量端点 |
| `CAPTURE_TOO_SHORT` | 抓包时长太短 | 增加 durationSeconds |
| `NO_PERMISSION` | 服务或驱动权限问题 | 检查服务状态/驱动安装 |
| `PCAP_EMPTY` | 只有 pcap header | 按 idle 处理 |
| `PCAP_UNSUPPORTED` | 不支持的 pcap 格式 | 提示 pcap/linktype 不支持 |

**返回示例**：

```json
{
  "diagnosis": "FILTER_TOO_STRICT",
  "confidence": 0.87,
  "recommendation": "Retry without endpoint filter, then analyze endpoint distribution.",
  "nextAction": {
    "tool": "usbpcap_smart_capture",
    "arguments": {
      "vendorId": "0x1a86",
      "productId": "0xffcc",
      "durationSeconds": 20,
      "appFilter": false
    }
  }
}
```

#### P1-5: 新增 `usbpcap_profile_device` 工具

**动机**：第一次分析某个设备时，AI 不知道活跃 endpoint、transferType 和 payload 长度。profile 工具用于短抓采样并生成推荐配置。

**接口定义**：

```json
{
  "name": "usbpcap_profile_device",
  "description": "短时间采样设备流量，识别活跃端点、传输类型和 payload 长度分布，并生成推荐抓包配置。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "vendorId": {"type": "string"},
      "productId": {"type": "string"},
      "durationSeconds": {"type": "integer", "default": 10}
    },
    "required": ["vendorId"]
  }
}
```

**输出包含**：

- 匹配设备和 interface
- 活跃 endpoint 列表
- transferType 分布
- payload 长度直方图
- 推荐的下一次抓包参数

**AI 执行规则**：

- 不知道 endpoint 时，先 profile，再精准抓。
- profile 返回多个活跃 endpoint 时，优先选择 packetCount/bytes 最高的 IN endpoint。
- profile 为空包时，进入 diagnose 流程。

#### P1-6: 新增 `usbpcap_analyze` 工具

**动机**：Go MCP 无 USB payload 分析能力。对比旧 Python MCP 的 `analyze` 能展示端点详情和 IO 统计。

**接口定义**：

```json
{
  "name": "usbpcap_analyze",
  "description": "分析 pcap 文件的 USB 流量，返回端点详情、payload 模式、帧头统计。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "pcapPath": {"type": "string", "description": "pcap 文件路径"},
      "deviceAddress": {"type": "integer", "description": "可选：仅分析指定设备"}
    },
    "required": ["pcapPath"]
  }
}
```

**输出包含**：
- 每个 endpoint 的包数、字节数分布
- payload 长度直方图（用于识别 510B config 帧 vs 512B data 帧 vs 2048B 大帧）
- USB payload 首字节模式统计（如 `0a81`=INIT, `0a87`=SESSION, `0a11`=CONFIG_A 等）

**实现位置**：新增 `internal/pcap/analyze.go`，复用 `summary.go` 的 USBPcap 头解析

#### P1-7: `usbpcap_export_data` 工具

**动机**：ATK-Logic/逻辑分析仪场景下，需从 pcap 提取指定 device+endpoint 的 payload 做信号分析。

**接口定义**：

```json
{
  "name": "usbpcap_export_data",
  "description": "从 pcap 提取指定设备的 payload 数据，支持 CSV/Hex/Raw 格式。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "pcapPath": {"type": "string"},
      "deviceAddress": {"type": "integer"},
      "endpoint": {"type": "string", "description": "例如 0x81 (IN)"},
      "minDataLen": {"type": "integer", "default": 1},
      "format": {"type": "string", "enum": ["hex", "csv", "raw"]},
      "outputPath": {"type": "string"}
    },
    "required": ["pcapPath"]
  }
}
```

**安全约束**：

- `pcapPath` 默认只允许读取 `captureDir` 下的 `.pcap` 文件。
- `outputPath` 不接受任意绝对路径，建议只接受文件名并写入 `captureDir/exports`。
- 禁止路径穿越，例如 `..\\..\\Windows\\...`。
- 限制最大导出字节数，避免 AI 误导出超大文件。

---

### 🟡 P1-A — AI 执行标准流程

#### 场景 1：用户只给 VID/PID，要抓数据

AI 应执行：

1. 调用 `usbpcap_smart_capture(vendorId, productId, durationSeconds=10, analyze=true)`。
2. 如果返回 `completed`，读取 summary/analyze。
3. 如果返回 `idle`，提示用户触发设备动作，然后执行返回的 `nextAction`。
4. 如果返回 `no_device`，提示用户检查设备连接。
5. 如果返回 `ambiguous_device`，向用户列出候选设备，不要猜。

#### 场景 2：用户要求持续抓直到有数据

AI 应执行：

1. 调用 `usbpcap_probe_device`。
2. 若唯一匹配，调用 `usbpcap_start_capture`。
3. 调用 `usbpcap_wait_capture_task`。
4. 如果超时但任务仍在运行，按用户目标决定继续等待或停止。

#### 场景 3：用户要分析已有 pcap

AI 应执行：

1. 调用 `usbpcap_analyze(pcapPath)`。
2. 如果需要导出 payload，再调用 `usbpcap_export_data`。
3. 不要先重新抓包，除非分析结果表明文件为空或格式不支持。

#### 场景 4：抓不到包

AI 应执行：

1. 调用 `usbpcap_diagnose_capture(taskId)`。
2. 按 `diagnosis` 和 `nextAction` 执行。
3. 不要重复相同失败参数超过一次。

---

### 🟡 P1-B — 结构化响应规范

所有抓包、等待、分析、诊断类工具应尽量返回以下字段：

```json
{
  "ok": true,
  "status": "completed",
  "message": "human readable message",
  "hint": "what the AI/user should do next",
  "retryable": true,
  "normalizedArguments": {},
  "nextAction": {
    "tool": "usbpcap_analyze",
    "arguments": {}
  }
}
```

#### 状态枚举

| status | 含义 | AI 应如何处理 |
|--------|------|---------------|
| `pending` | 任务已创建但未开始 | 等待或查询任务 |
| `running` | 正在抓包 | 调用 `wait_capture_task` |
| `completed` | 抓到数据并完成 | 进入 analyze/export |
| `idle` | 找到设备但无流量 | 提示用户触发设备动作后重试 |
| `no_device` | 未找到匹配设备 | 提示用户检查连接或 VID/PID |
| `no_match` | on-match 模式下未匹配到包 | 放宽过滤条件 |
| `ambiguous_device` | 多个候选设备 | 让用户选择，不要猜 |
| `filter_too_strict` | 过滤条件过严 | 去掉 endpoint/transferType 重试 |
| `failed` | 执行失败 | 调用 diagnose 或显示错误 |
| `stopped` | 用户/系统停止 | 不自动重试 |
| `timeout` | 等待超时 | 查询任务或继续等待 |

#### 参数自动规范化

服务端应宽容接受常见 AI 输入错误：

| AI 输入 | 规范化结果 |
|---------|------------|
| `"1a86"` | `"0x1a86"` |
| `"0X1A86"` | `"0x1a86"` |
| `"81"` | `"0x81"` |
| `"USBPcap2"` | `"\\\\.\\USBPcap2"` |
| `durationSeconds: 0` | 默认 10 |
| 有 endpoint 但 `appFilter=false` | 自动设为 true，或返回明确错误 |

响应中应返回：

```json
{
  "normalizedArguments": {
    "vendorId": "0x1a86",
    "endpoint": "0x81",
    "interface": "\\\\.\\USBPcap2"
  }
}
```

---

### 🟢 P2 — UX 打磨

#### P2-1: deviceDistribution key 格式统一

**现状**：Go summary 用 `"0x10"` 为 key，list_devices 返回 `"address": 16`（十进制）。

**建议**：统一用 `"0x10"` 格式（与 USB 规范一致），或提供 `deviceDisplayName` 映射。

#### P2-2: `outputFileName` 参数支持自定义

**现状修订**：当前 Go service 中 `outputFileName` 已通过 `defaultOutputPath()` 生效，且使用 `filepath.Base()` 截断路径。

**期望**：补充单元测试，确保：

- 用户指定 `outputFileName: "my-test.pcap"` 时使用该名称。
- 用户传入包含路径的文件名时，只取 basename，防止路径穿越。
- 空值仍使用时间戳生成。

**实现位置**：`internal/service/server.go` `defaultOutputPath()`

#### P2-3: 任务 TTL 自动清理

**现状**：已完成的历史任务永久保留在内存中（最多 `maxHistoryTasks` 条）。

**建议**：增加基于时间的清理（例如 1 小时后自动移除历史任务），释放内存。

#### P2-4: `usbpcap_stop_capture` 应支持按 taskId 停止

**现状**：`stopCapture` 只能停止当前运行的捕获，无法指定 taskId。

**期望**：支持 `usbpcap_stop_capture(taskId)` 精确停止。

---

### 🔵 P3 — 长线优化

#### P3-1: 支持 pcapng 格式

**现状**：`pcap.Summarize()` 只支持 link type 249（USBPcap pcap 格式）。未来 USBPcapCap 可能输出 pcapng（`.pcapng`）。

**建议**：增加 pcapng Section Header Block / Interface Description Block 解析。

#### P3-2: 支持捕获后自动通知（增强项）

**现状**：异步 `start_capture` → 轮询 `get_capture_task`。这在 AI Agent 场景下效率低，弱模型也容易忘记轮询。

**建议**：

1. 先实现 `usbpcap_wait_capture_task`，让 AI 有稳定的显式等待方式。
2. 再支持 MCP `notifications` 机制，捕获完成后自动通知客户端。
3. notifications 只能作为增强项，因为不同 MCP 客户端对 notification 支持不一致。

**AI 规则**：

- 如果有 `wait_capture_task`，AI 优先使用 wait。
- 如果客户端支持 notification，可减少轮询，但不要依赖 notification 完成核心流程。

#### P3-3: 多实例捕获支持

**现状**：同一时间只能运行一个 capture (`activeCapture` 锁)。

**建议**：支持同时在不同 interface 上捕获（如 USBPcap1 + USBPcap2 同时抓），每个 interface 一个 capture slot。

#### P3-4: WebSocket/HTTP API

**现状**：仅通过 named pipe 暴露 IPC 接口，MCP 必须作为 proxy。

**建议**：增加 HTTP REST API（`/api/v1/capture/start` 等），方便非 MCP 客户端使用。可作为 service 的可选监听器。

---

## 四、实现优先级时间线

| 阶段 | 任务 | 预估工时 |
|------|------|---------|
| **Week 1** | P0-1 空闲设备状态 + P1-1 probe_device | 0.5d |
| **Week 1** | P1-2 wait_capture_task + 结构化 nextAction | 0.5d |
| **Week 1-2** | P1-3 smart_capture | 1d |
| **Week 2** | P1-6 analyze 工具 | 1d |
| **Week 2** | P1-4 diagnose_capture + 状态枚举补齐 | 0.5d |
| **Week 2-3** | P1-5 profile_device | 1d |
| **Week 3** | P1-7 export_data 工具 | 1d |
| **Week 3** | P2-1/2/3 格式统一、命名测试、清理 | 0.5d |
| **Week 4** | P2-4 stopCapture 精确停止 + P3-2 notifications 调研 | 0.5d |

---

## 五、测试检查清单

- [ ] `start_capture` + VID/PID + 空闲设备 → 返回 `idle` 状态
- [ ] `capture_once` + 60s duration → 明确验证实际超时边界；若不稳定，文档建议改用 `start_capture + wait_capture_task`
- [ ] `probe_device(vendorId=0x1a86)` → 自动返回 `{interface:"\\\\.\\USBPcap2", address:16}`
- [ ] `start_capture` 后响应包含 `nextAction.tool=usbpcap_wait_capture_task`
- [ ] `wait_capture_task(taskId)` → 任务完成后返回 summary 和下一步建议
- [ ] `smart_capture(vendorId=0x1a86)` → 自动 probe、抓包、等待、返回 summary/analyze
- [ ] `smart_capture` 遇到多个匹配设备 → 返回 `ambiguous_device`，不自动猜测
- [ ] `smart_capture` 遇到空闲设备 → 返回 `idle` 和触发设备活动的 hint
- [ ] `diagnose_capture(taskId)` → 能区分 `DEVICE_IDLE` / `FILTER_TOO_STRICT` / `NO_DEVICE`
- [ ] `profile_device(vendorId=0x1a86)` → 返回活跃 endpoint 和推荐抓包参数
- [ ] `analyze(pcapPath)` → 返回端点统计、payload 模式
- [ ] `export_data(deviceAddress=16, endpoint=0x81, format=csv)` → 正确 CSV 输出
- [ ] `outputFileName: "custom.pcap"` → 输出文件名为 `custom.pcap`
- [ ] `outputFileName: "..\\evil.pcap"` → 只使用 basename，不发生路径穿越
- [ ] `vendorId: "1a86"` / `endpoint: "81"` / `interface: "USBPcap2"` → 自动规范化
- [ ] `deviceDistribution` key 格式统一为 `"0x10"`
- [ ] `stopCapture("capture-5")` → 精确停止指定 task
