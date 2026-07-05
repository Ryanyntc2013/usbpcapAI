# USBPcapCap AI 抓包能力改造计划、设计及实现方案

## 1. 目标

将现有 `USBPcapCap` 改造为更适合本机 AI 工具调用的 USB 抓包能力底座，并新增 Go 实现的本机 MCP 与服务层。

核心目标：

1. 保留并增强现有命令行抓包能力。
2. 新增本机 MCP 接口，供 AI 工具调用。
3. 支持根据已连接设备的 `vendor ID` 进行精确过滤。
4. 支持可选附带抓取新插入的任意设备。
5. 抓包时不弹 UAC，改为 Windows Service 模式运行。
6. MCP 返回 pcap 文件路径、摘要信息和简要解析结果。
7. 修复 `USBPcapCap` 在终端、管道、PowerShell、AI 调用场景下的乱码问题。
8. 保留并扩展应用层 VID/PID/endpoint 过滤能力，便于不改驱动时逐步增强过滤策略。
9. 支持“命中条件后才开始写盘”的触发式存储，便于长时间监测。
10. 提供充分、清晰、机器友好的命令行帮助与错误提示。

## 2. 非目标

本阶段不做以下事项：

1. 不重写 USBPcap 内核驱动。
2. 不实现驱动级 VID/PID 过滤。
3. 不保证对新插入设备按 VID 精确过滤。
4. 不在 MCP 返回完整 pcap 二进制内容。
5. 不依赖 Wireshark/tshark 做基础摘要解析。
6. 不在第一阶段实现驱动态 endpoint 过滤，endpoint 过滤先在应用层完成。

## 3. 约束与边界

### 3.1 已连接设备 VID 精确过滤

当前驱动只支持 USB address 过滤，不支持 VID/PID 过滤。用户态可以通过设备枚举拿到 `USB_DEVICE_DESCRIPTOR.idVendor` 和 `idProduct`，再将匹配设备转换为 address list，复用现有 address filter。

流程：

```text
--vendor-id 0x1234
  -> 枚举当前 root hub 下已连接设备
  -> 匹配 USB_DEVICE_DESCRIPTOR.idVendor
  -> 提取 deviceAddress
  -> 生成 --devices address list
  -> 调用现有驱动 address filter 抓包
```

该方案可保证“启动抓包时已经连接的目标设备”精确过滤。

### 3.2 新插入设备语义

可支持参数：

```powershell
--vendor-id 0x1234 --capture-from-new-devices
```

语义定义为：

- 已连接设备：按 VID/PID 精确过滤。
- 新插入设备：任何 VID/PID 都会被捕获。

原因：当前驱动的新设备机制是通过 address `0` 启用“新设备自动加入过滤”，驱动侧无法在当前结构中按 VID 判断。

### 3.3 应用层过滤边界

为保证可扩展性，过滤分为两层：

1. 驱动层过滤：使用现有 address filter，减少无关设备进入用户态。
2. 应用层过滤：在 `USBPcapCap` 读取到 pcap/USBPcap packet 后，再按 VID、PID、endpoint、transfer type 等条件决定是否写入文件或触发开始存储。

第一阶段的精确 VID/PID 已连接设备过滤仍优先通过“VID/PID -> address list -> 驱动 address filter”实现。应用层 VID/PID 过滤作为保留能力，主要用于：

- 后续兼容更复杂的匹配规则。
- 支持“抓所有新设备，但只在命中特定帧后开始存储”。
- 支持 endpoint 级别过滤，而不修改驱动。
- 支持长时间监测中的触发式写盘策略。

应用层 endpoint 过滤依赖 USBPcap packet header 中的 device address、endpoint 和 transfer type。VID/PID 与 address 的对应关系来自抓包启动前的枚举快照，后续可由 service 周期性刷新设备映射。

### 3.4 触发式存储边界

触发式存储定义为：程序可以长时间读取驱动数据，但在捕捉到满足条件的帧之前不创建或不写入最终 pcap 文件；命中条件后才开始写入 pcap header 和后续匹配数据。

建议支持两种模式：

1. `immediate`：默认模式，抓包开始即写盘。
2. `on-match`：触发模式，只有发现满足条件的帧后才开始写盘。

可选扩展：

- `--pretrigger-packets <n>`：在内存环形缓冲中保留触发前最近 N 个匹配/原始包。
- `--pretrigger-bytes <n>`：限制触发前缓存最大字节数。
- `--idle-timeout <seconds>`：触发后如果长时间没有新匹配帧则自动结束。
- `--max-file-size <bytes>`：限制单个 pcap 文件大小，避免长期运行撑满磁盘。

第一阶段可以先实现 `on-match`，不实现 pretrigger；pretrigger 作为后续增强。

### 3.5 免安装边界

三个用户态 exe 可以放在任意目录：

```text
USBPcapCap.exe
USBPcapService.exe
USBPcapMCP.exe
```

但完整抓包不能完全免安装：

| 项目 | 是否可便携 | 说明 |
| --- | --- | --- |
| `USBPcapMCP.exe` | 是 | 本机 AI 工具直接调用 |
| `USBPcapCap.exe` | 是 | 依赖系统中已安装并可用的 USBPcap 驱动 |
| `USBPcapService.exe` | exe 可便携 | 作为服务运行前需要注册服务 |
| `USBPcapDriver.sys` | 否 | 必须安装到系统并生效 |
| 抓包时无 UAC | 是 | 前提是服务已安装并运行 |
| 首次部署完全无管理员权限 | 否 | 驱动安装和服务注册需要管理员权限 |

## 4. 总体架构

```text
本机 AI 工具 / MCP Client
        |
        | MCP stdio
        v
USBPcapMCP.exe         Go
  - MCP 工具暴露
  - 参数校验
  - 请求转发
  - 返回文件路径和摘要
        |
        | Named Pipe / Local IPC
        v
USBPcapService.exe     Go，Windows Service，LocalSystem
  - 抓包任务管理
  - 启动/停止 USBPcapCap
  - 输出目录控制
  - 超时控制
  - 触发式存储策略
  - pcap 摘要解析
        |
        | 子进程调用
        v
USBPcapCap.exe         C
  - USBPcap 设备枚举
  - VID/PID -> deviceAddress
  - 应用层 VID/PID/endpoint 过滤
  - 命中条件后开始存储
  - 命令行抓包
  - JSON 输出
  - UTF-8 输出修复
        |
        | IOCTL / ReadFile
        v
USBPcapDriver.sys
  - 内核态 URB 捕获
  - address filter
```

## 5. 组件设计

### 5.1 `USBPcapCap.exe`

职责：

1. 保留现有 extcap 和传统命令行能力。
2. 新增机器可读 JSON 输出。
3. 新增 VID/PID 过滤能力。
4. 新增抓包时长控制。
5. 修复终端乱码。
6. 新增应用层过滤与触发式存储能力。
7. 新增分层帮助与示例提示。

建议新增参数：

```powershell
--json
--list-interfaces
--list-devices
--vendor-id <hex-or-dec>
--product-id <hex-or-dec>
--auto-interface
--duration <seconds>
--summary
--no-interactive
--app-filter
--endpoint <hex-or-dec>
--transfer-type <control|bulk|interrupt|isochronous|unknown>
--store-mode <immediate|on-match>
--pretrigger-packets <count>
--pretrigger-bytes <bytes>
--idle-timeout <seconds>
--max-file-size <bytes>
```

示例：

```powershell
USBPcapCap.exe --list-interfaces --json
USBPcapCap.exe --list-devices --device \\.\USBPcap1 --json
USBPcapCap.exe --device \\.\USBPcap1 --vendor-id 0x1234 --output out.pcap --duration 10 --json
USBPcapCap.exe --auto-interface --vendor-id 0x1234 --output out.pcap --duration 10 --json
USBPcapCap.exe --device \\.\USBPcap1 --vendor-id 0x1234 --endpoint 0x81 --app-filter --output out.pcap --duration 60 --json
USBPcapCap.exe --device \\.\USBPcap1 --vendor-id 0x1234 --endpoint 0x81 --store-mode on-match --output out.pcap --duration 3600 --json
```

#### 5.1.1 JSON 接口

接口列表输出：

```json
{
  "interfaces": [
    {
      "name": "\\\\.\\USBPcap1",
      "displayName": "USBPcap1",
      "hub": "..."
    }
  ]
}
```

设备列表输出：

```json
{
  "interface": "\\\\.\\USBPcap1",
  "devices": [
    {
      "address": 7,
      "port": 2,
      "parentAddress": 0,
      "vendorId": "0x1234",
      "productId": "0xabcd",
      "isHub": false,
      "description": "USB Composite Device"
    }
  ]
}
```

抓包结果输出：

```json
{
  "ok": true,
  "output": "E:\\captures\\usbpcap-20260703-001.pcap",
  "storeMode": "immediate",
  "triggered": true,
  "matchedDevices": [
    {
      "interface": "\\\\.\\USBPcap1",
      "address": 7,
      "vendorId": "0x1234",
      "productId": "0xabcd"
    }
  ]
}
```

#### 5.1.2 乱码修复方案

当前输出路径中存在宽字符与控制台/重定向处理不一致的问题。改造原则：

1. 控制台输出：使用 `WriteConsoleW`。
2. 管道/重定向/JSON 输出：统一输出 UTF-8，无 BOM。
3. 程序启动时尽量设置控制台代码页：

```c
SetConsoleOutputCP(CP_UTF8);
SetConsoleCP(CP_UTF8);
```

4. JSON 输出不要使用 UTF-16。
5. `--json` 模式下 stdout 只输出 JSON，错误和诊断进入 stderr。

#### 5.1.3 VID/PID 到 address list

新增内部结构：

```c
typedef struct device_match {
    USHORT address;
    USHORT vendor_id;
    USHORT product_id;
    char interface_name[MAX_PATH];
} device_match;
```

实现逻辑：

1. 调用现有 `enumerate_all_connected_devices()`。
2. 在回调中读取 `PUSB_DEVICE_DESCRIPTOR desc`。
3. 比较 `desc->idVendor` 和可选 `desc->idProduct`。
4. 生成逗号分隔 address list。
5. 调用现有 `USBPcapInitAddressFilter()`。

#### 5.1.4 应用层 VID/PID/endpoint 过滤

应用层过滤用于在不修改驱动的情况下增强过滤表达能力。建议新增统一过滤配置：

```c
typedef struct app_capture_filter {
    BOOLEAN enabled;
    BOOLEAN has_vendor_id;
    BOOLEAN has_product_id;
    BOOLEAN has_endpoint;
    BOOLEAN has_transfer_type;
    USHORT vendor_id;
    USHORT product_id;
    UCHAR endpoint;
    UCHAR transfer_type;
} app_capture_filter;
```

过滤流程：

```text
driver read
  -> parse pcap record header
  -> parse USBPcap packet header
  -> device address -> VID/PID 映射
  -> endpoint / transfer type 判断
  -> matched ? write/trigger : drop
```

规则建议：

1. 默认不启用应用层过滤，保持现有性能和兼容性。
2. 传入 `--app-filter` 或 endpoint/transfer 条件时启用。
3. 如果启用了 `--vendor-id`/`--product-id`，且对应 address 已经在驱动层过滤，应用层仍可二次校验。
4. endpoint 支持十六进制或十进制，例如 `0x81`、`129`。
5. transfer type 支持 `control`、`bulk`、`interrupt`、`isochronous`、`unknown`。

#### 5.1.5 触发式存储

新增存储模式：

```powershell
--store-mode immediate
--store-mode on-match
```

行为：

- `immediate`：创建文件并立即写入 pcap header，所有通过过滤的帧写入文件。
- `on-match`：读取和解析持续进行，但在第一帧满足应用层过滤或触发条件前不写最终文件；命中后写入 pcap header，并从触发帧开始写入。

长时间监测推荐命令：

```powershell
USBPcapCap.exe --device \\.\USBPcap1 --vendor-id 0x1234 --endpoint 0x81 --app-filter --store-mode on-match --duration 86400 --output monitor.pcap --json --no-interactive
```

返回结果需要区分未触发和已触发：

```json
{
  "ok": true,
  "triggered": false,
  "output": null,
  "reason": "No packet matched trigger conditions before timeout"
}
```

设计注意：

1. `on-match` 模式下，如果超时前没有命中，默认不生成空 pcap 文件。
2. 可通过后续参数扩展支持生成空摘要文件，但不建议默认这样做。
3. pcap header 必须在首次写入真实帧前写入。
4. 注入 descriptors 时要谨慎：如果 `--inject-descriptors` 与 `on-match` 同时启用，应在触发后再写入 pcap header 和 descriptors。
5. 长时间运行必须限制最大时长、最大文件大小和最大内存缓存。

#### 5.1.6 命令行帮助设计

帮助信息需要分层，避免只给一大段参数列表。

建议支持：

```powershell
USBPcapCap.exe --help
USBPcapCap.exe --help capture
USBPcapCap.exe --help filter
USBPcapCap.exe --help json
USBPcapCap.exe --help examples
```

帮助内容要求：

1. 明确区分驱动层过滤和应用层过滤。
2. 明确说明 `--capture-from-new-devices` 会抓取任意新设备，不按 VID/PID 精确过滤。
3. 给出 VID/PID/endpoint 的十六进制示例。
4. 给出 PowerShell 可直接复制的示例。
5. `--json` 模式下错误也应提供稳定错误码。
6. 对没有驱动、权限不足、未匹配设备、输出路径无权限给出明确修复建议。

示例错误：

```json
{
  "ok": false,
  "errorCode": "NO_MATCHED_DEVICE",
  "message": "No connected USB device matched vendorId=0x1234 productId=any on \\\\.\\USBPcap1.",
  "hint": "Run USBPcapCap.exe --list-devices --device \\\\.\\USBPcap1 --json to inspect current devices."
}
```

### 5.2 `USBPcapService.exe`

语言：Go。

运行方式：Windows Service，建议 LocalSystem。

职责：

1. 接收本机 IPC 请求。
2. 校验请求参数。
3. 启动 `USBPcapCap.exe` 执行抓包。
4. 管理抓包任务生命周期。
5. 控制输出目录，避免任意路径写入。
6. 抓包结束后解析 pcap 生成摘要。
7. 返回任务结果给 `USBPcapMCP.exe`。

建议命令：

```powershell
USBPcapService.exe install --capture-dir .\captures
USBPcapService.exe uninstall
USBPcapService.exe start
USBPcapService.exe stop
USBPcapService.exe status
USBPcapService.exe run
```

服务启动后默认从自身所在目录寻找：

```text
USBPcapCap.exe
```

也可通过配置指定绝对路径。

#### 5.2.1 IPC 设计

推荐使用 Windows Named Pipe。

管道名：

```text
\\.\pipe\usbpcap-ai-service
```

安全要求：

1. 仅允许本机访问。
2. 默认允许当前交互用户和 Administrators 访问。
3. 不暴露网络监听端口。
4. 请求中不允许任意命令执行。
5. 输出文件必须限制在配置的 capture 目录内。

#### 5.2.2 抓包请求

```json
{
  "action": "captureOnce",
  "vendorId": "0x1234",
  "productId": "0xabcd",
  "durationSeconds": 10,
  "captureNewDevices": false,
  "appFilter": true,
  "endpoint": "0x81",
  "transferType": "bulk",
  "storeMode": "on-match",
  "idleTimeoutSeconds": 30,
  "maxFileSizeBytes": 104857600,
  "interface": "\\\\.\\USBPcap1",
  "autoInterface": false
}
```

响应：

```json
{
  "ok": true,
  "pcapPath": "E:\\captures\\usbpcap-20260703-001.pcap",
  "triggered": true,
  "storeMode": "on-match",
  "summary": {
    "packetCount": 1203,
    "sizeBytes": 845332,
    "durationMs": 10000,
    "matchedDevices": [
      {
        "interface": "\\\\.\\USBPcap1",
        "address": 7,
        "vendorId": "0x1234",
        "productId": "0xabcd"
      }
    ],
    "transferTypes": {
      "control": 12,
      "bulk": 1030,
      "interrupt": 161,
      "isochronous": 0,
      "unknown": 0
    }
  }
}
```

### 5.3 `USBPcapMCP.exe`

语言：Go。

运行方式：普通用户进程，由本机 AI 工具以 stdio MCP 方式启动。

职责：

1. 暴露 MCP tools。
2. 将 MCP 请求转为 service IPC 请求。
3. 返回结构化结果。
4. 不直接以管理员权限运行。
5. 不直接访问驱动。

建议 MCP tools：

| Tool | 说明 |
| --- | --- |
| `usbpcap_list_interfaces` | 列出 USBPcap 抓包接口 |
| `usbpcap_list_devices` | 列出指定接口下已连接 USB 设备 |
| `usbpcap_capture_once` | 按条件抓包一次并返回路径和摘要 |
| `usbpcap_capture_status` | 查询当前服务与任务状态 |
| `usbpcap_stop_capture` | 停止指定抓包任务，后续需要长任务时使用 |
| `usbpcap_help` | 返回工具参数说明、过滤语义和示例 |

第一阶段优先实现：

1. `usbpcap_list_interfaces`
2. `usbpcap_list_devices`
3. `usbpcap_capture_once`
4. `usbpcap_capture_status`
5. `usbpcap_help`

## 6. 目录规划

建议新增：

```text
USBPcapAI/
  go.mod
  cmd/
    usbpcap-mcp/
      main.go
    usbpcap-service/
      main.go
  internal/
    ipc/
    capture/
    pcap/
    usbpcapcmd/
```

最终发布目录：

```text
usbpcap-ai/
  USBPcapCap.exe
  USBPcapService.exe
  USBPcapMCP.exe
  config.json
  captures/
```

## 7. 安全设计

1. MCP 进程不提权。
2. 抓包能力只通过本机 service 暴露。
3. Service 不开放 TCP 端口，默认只用 Named Pipe。
4. 所有输出文件限制在 configured capture directory。
5. 禁止请求直接传入任意命令行片段。
6. `USBPcapCap` 参数由 Go 层按白名单拼接，不做 shell 拼接。
7. 限制最大抓包时长、最大缓冲区、最大输出文件大小。
8. 日志中不记录敏感 payload 内容，仅记录任务元数据。
9. 触发式存储默认不写入未命中流量，降低长期监测中意外保存敏感数据的风险。
10. 帮助提示中必须明确长期监测的磁盘占用限制和隐私风险。

## 8. pcap 摘要解析

Go 层读取 pcap 文件头和 USBPcap packet header，生成轻量摘要。

第一阶段统计：

1. 文件大小。
2. 包数量。
3. 抓包持续时间。
4. 设备 address 分布。
5. endpoint 分布。
6. transfer type 分布。
7. 错误包数量粗略统计。
8. 首次命中时间和触发条件。
9. 应用层过滤丢弃帧数量。

不做深度协议解析。深度解析由后续流程基于 `pcapPath` 处理。

## 9. 实施计划

### 阶段 1：`USBPcapCap` 命令行现代化

目标：让 C 程序先成为稳定、可脚本调用的抓包 CLI。

任务：

1. 新增 `--json` 输出模式。
2. 新增 `--list-interfaces`。
3. 新增 `--list-devices --device <name>`。
4. 新增 `--vendor-id` / `--product-id`。
5. 新增 `--auto-interface`。
6. 新增 `--duration`。
7. 新增 `--no-interactive`，避免服务场景误入交互。
8. 修复 UTF-8/控制台/管道输出乱码。
9. 保持原 extcap 参数兼容。
10. 新增 `--app-filter`、`--endpoint`、`--transfer-type`。
11. 新增 `--store-mode immediate|on-match`。
12. 新增分层帮助：`--help capture/filter/json/examples`。

验收：

```powershell
USBPcapCap.exe --list-interfaces --json
USBPcapCap.exe --list-devices --device \\.\USBPcap1 --json
USBPcapCap.exe --device \\.\USBPcap1 --vendor-id 0x1234 --output out.pcap --duration 5 --json --no-interactive
USBPcapCap.exe --device \\.\USBPcap1 --vendor-id 0x1234 --endpoint 0x81 --app-filter --store-mode on-match --output out.pcap --duration 3600 --json --no-interactive
```

### 阶段 2：Go Service

目标：实现无 UAC 抓包通道。

任务：

1. 新建 `USBPcapAI` Go module。
2. 实现 Windows Service install/start/stop/status。
3. 实现 Named Pipe IPC。
4. 实现调用 `USBPcapCap.exe`。
5. 实现抓包输出目录管理。
6. 实现任务超时和停止。
7. 实现 pcap 摘要解析。
8. 实现 service 层抓包策略校验，包括长期监测、触发存储、文件大小限制。

验收：

```powershell
USBPcapService.exe install --capture-dir .\captures
USBPcapService.exe start
USBPcapService.exe status
```

### 阶段 3：Go MCP

目标：让本机 AI 工具可调用 USB 抓包能力。

任务：

1. 实现 stdio MCP server。
2. 注册 MCP tools。
3. 对接 service IPC。
4. 返回结构化 JSON 结果。
5. 增加错误信息和用户提示。
6. 实现 `usbpcap_help`，让 AI 能向用户解释参数、过滤边界和示例。

验收：

- AI 工具可列出接口。
- AI 工具可列出设备。
- AI 工具可按 VID 抓包一次。
- 返回 pcap 路径和摘要。

### 阶段 4：打包与发布

目标：形成可复制目录和一次性安装流程。

任务：

1. 生成三个 exe。
2. 提供默认 `config.json`。
3. 检查服务从自身目录定位 `USBPcapCap.exe`。
4. 检查不同目录运行。
5. 检查没有驱动时的错误提示。
6. 检查服务未安装时 MCP 的错误提示。

## 10. 风险与应对

| 风险 | 影响 | 应对 |
| --- | --- | --- |
| 新插入设备不能按 VID 精确过滤 | 用户误解过滤语义 | 明确参数说明和返回提示 |
| 服务路径移动后失效 | 抓包失败 | 服务启动时从自身目录寻找 CMD，或安装时写入绝对路径 |
| 没安装驱动 | 无法抓包 | CMD 和 MCP 返回明确错误 |
| 输出乱码 | AI 解析失败 | JSON 统一 UTF-8，无 BOM |
| 权限不足 | 抓包失败/UAC | 通过 LocalSystem service 执行 |
| 任意路径写入 | 安全风险 | Service 限制 capture 目录 |
| 子进程残留 | 资源泄露 | Service 管理 process group/job，超时清理 |
| 长期监测磁盘占满 | 系统稳定性风险 | `maxFileSizeBytes`、`durationSeconds`、`idleTimeoutSeconds` 默认限制 |
| 应用层过滤导致性能下降 | 高流量设备丢包或 CPU 占用高 | 默认关闭应用层过滤，仅在需要 endpoint/trigger 时启用 |
| `on-match` 未触发导致用户误判 | 以为抓包失败 | 返回 `triggered=false`、明确 reason 和下一步建议 |

## 11. 验收标准

1. `USBPcapCap.exe --list-interfaces --json` 输出合法 UTF-8 JSON。
2. `USBPcapCap.exe --list-devices --device ... --json` 能输出 VID/PID/address。
3. `USBPcapCap.exe --vendor-id ... --duration ...` 可抓取已连接目标设备。
4. PowerShell、cmd、重定向、Go 子进程读取均无乱码。
5. Service 安装后，普通用户运行 MCP 抓包不弹 UAC。
6. MCP 返回 pcap 路径、文件大小、包数量、transfer type 摘要。
7. 未安装驱动、未启动服务、未匹配设备时返回明确错误。
8. endpoint 应用层过滤能只写入指定 endpoint 的帧。
9. `--store-mode on-match` 在未命中时不生成空 pcap，并返回 `triggered=false`。
10. `--help capture/filter/json/examples` 输出清晰、可复制、无乱码。

## 12. 推荐最终用户流程

首次部署：

```powershell
USBPcapService.exe install --capture-dir .\captures
USBPcapService.exe start
```

AI 工具配置 MCP：

```powershell
USBPcapMCP.exe
```

抓包请求示例：

```json
{
  "vendorId": "0x1234",
  "endpoint": "0x81",
  "durationSeconds": 10,
  "captureNewDevices": false,
  "appFilter": true,
  "storeMode": "on-match"
}
```

返回示例：

```json
{
  "pcapPath": "E:\\captures\\usbpcap-20260703-001.pcap",
  "triggered": true,
  "summary": {
    "packetCount": 1203,
    "sizeBytes": 845332,
    "transferTypes": {
      "control": 12,
      "bulk": 1030,
      "interrupt": 161,
      "isochronous": 0
    }
  }
}
```
