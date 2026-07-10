# USBPCap AI MCP 测试 Bug 清单

> 日期: 2026-07-10  
> 测试覆盖: USBPcapCap (C) / USBPcapService (Go) / USBPcapMCP (Go)  
> 鼠标设备: 0x1d57:0xfa60 (USB Composite Device)  
> 版本: v0.4.0-dev
> 修复提交: `4b2015a`

---

## 修复状态总览

| Bug | 严重度 | 状态 | 提交 |
|-----|--------|------|------|
| BUG-TRIGGERED-FALSE | 🔴 HIGH | ✅ 已修复 | `4b2015a` |
| BUG-ONMATCH-WRITES-UNTRIGGERED | 🔴 HIGH | ✅ 已修复 (同 Bug1 根因) | `4b2015a` |
| BUG-INVALID-WRITE-HANDLE | 🟡 MED | ✅ 已修复 | `4b2015a` |
| BUG-JOB-FLAGS (Go 侧) | 🟡 MED | ✅ 已修复 | `4b2015a` |
| BUG-JOB-FLAGS (C 侧) | 🔵 LOW | ⏸️ 暂缓 (Win7 兼容性风险) | 未修复 |
| BUG-HELP-EXAMPLES-RELEASE | 🔵 LOW | ⏸️ 待调查 (Debug 版正常) | 未修复 |

---

## 严重度定义

| 级别 | 标签 | 定义 |
|------|------|------|
| 🔴 HIGH | 功能阻断 | 违反核心设计契约，必须修复后才能发布 |
| 🟡 MED | 功能缺陷 | 功能可工作但不完全符合规范，建议发布前修复 |
| 🔵 LOW | 轻微/UI | 不影响功能正确性，可在后续迭代修复 |

---

## Bug 1 🔴 HIGH: `triggered` 字段始终返回 `false`

### ID
BUG-TRIGGERED-FALSE

### 现象
无论使用哪种 `--store-mode`、抓到多少包，JSON 输出中 `triggered` 字段始终为 `false`。  
immediate 模式抓到 1080 包 → `triggered=false`  
on-match 模式抓到 872 包 → `triggered=false`

### 根因分析

**代码位置**: `USBPcapCMD/cmd.c` 行 2770 + `USBPcapCMD/thread.c` 行 183

**竞态条件**: `data.triggered` 的生命周期如下：

```
主线程                           worker 线程
  |                                |
  | data.triggered = FALSE         |
  | start_capture(&data) ---->     |
  |                                | 开始抓包
  |  ← 立即返回（worker 已启动）    | 初始化 write_handle
  |                                | begin_output_stream()
  |                                |   → data.triggered = TRUE    ← 稍后才执行
  | print JSON: data.triggered     |
  |   → 仍然是 FALSE !!            |
```

`begin_output_stream()` 在 worker 线程中设置 `data->triggered = TRUE`，但主线程在 `start_capture()` 返回后立刻打印 JSON，此时 worker 线程可能还没来得及执行到 `begin_output_stream()`。

### 修复建议

```c
// 方案 A（推荐）: 对于 immediate 模式，在主线程中直接设 triggered=TRUE
if (data.store_mode == USBPCAP_STORE_MODE_IMMEDIATE) {
    data.triggered = TRUE;
}

// 方案 B: ensure_output_stream_started() 同步等待 worker 完成文件头写入
```

**影响面**: BL-20M 阻断

---

## Bug 2 🔴 HIGH: on-match 未触发时仍写入 pcap 文件

### ID
BUG-ONMATCH-WRITES-UNTRIGGERED

### 现象
`--store-mode on-match --duration 8` 且鼠标静止，从设计预期来看应该不生成 pcap 文件，但实际上生成了 41KB / 872 包的 pcap 文件。

### 根因分析

**代码位置**: `USBPcapCMD/thread.c` 行 158-183 (`begin_output_stream`)

`begin_output_stream()` 在首次调用时无条件执行：
1. `open_output_handle_if_needed()` — 创建/打开输出文件
2. `write_data()` — 写入 pcap header
3. **设置 `data->triggered = TRUE`**

对于 on-match 模式，逻辑应为：
- 匹配前: 只缓存（不写文件）
- 匹配后: 写入 pcap header + 缓存帧 + 后续帧

但当前实现中，`begin_output_stream()` 被调用时（通常是第一帧到达时）就写入了 pcap header 并将 triggered 置 TRUE。真正的 app_filter 匹配发生在更早的 `app_packet_matches()`，但此函数只返回 TRUE/FALSE，没有阻止 `begin_output_stream` 的写入。

### 修复建议

```c
// 在 begin_output_stream() 中增加 on-match 判断
static BOOL begin_output_stream(...) {
    if (data->store_mode == USBPCAP_STORE_MODE_ON_MATCH && !data->matched_once) {
        return TRUE;  // 只准备，不写文件
    }
    // ... 原有写入逻辑
}
```

**影响面**: 违反设计文档 §3.4 "触发式存储" 和 §5.1.5 "on-match 模式"

---

## Bug 3 🟡 MED: `Thread started with invalid write handle!` stderr 消息

### ID
BUG-INVALID-WRITE-HANDLE

### 现象
每次抓包时 stderr 输出 `Thread started with invalid write handle!` 消息。该消息仅出现在 stderr，不影响抓包结果。

### 根因分析

**代码位置**: `USBPcapCMD/thread.c`

worker 线程创建时 `data->write_handle` 为 `INVALID_HANDLE_VALUE`。线程启动后通过 `open_output_handle_if_needed()` 初始化输出句柄，但在此之前线程的某些代码路径（可能是 CRT 文件操作）检测到无效句柄并发出警告。

典型的 Windows CRT 调试行为：当 `_beginthreadex` 创建的线程在 CRT 初始化期间检测到标准句柄无效时，CRT 会发出诊断。

### 修复建议

```c
// 方案 A: 在创建 worker 线程前先设好 write_handle
data->write_handle = GetStdHandle(STD_OUTPUT_HANDLE);

// 方案 B: 忽略该消息（不影响功能）
// 但 stderr 噪声会影响 AI 工具解析
```

**影响面**: 低功能影响，但 stderr 噪声对 AI 工具调用有干扰

---

## Bug 4 🟡 MED: `Unhandled job limit flags 0x00000000` 警告

### ID
BUG-JOB-FLAGS

### 现象
每次 Go runner 启动 USBPcapCap.exe 时，stderr 输出:  
`Unhandled job limit flags 0x00000000`

### 根因分析

**代码位置**: `USBPcapAI/internal/usbpcapcmd/runner.go` 行 169-176

```go
info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
    BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
        LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
}
```

`KILL_ON_JOB_CLOSE` (0x00002000) 被设置，但 MSVC 运行时的 `_beginthreadex` 在子进程中检测到"只有 KILL_ON_JOB_CLOSE 而没有其他限制标志"时，认为这是一个不完整的配置并输出警告。

### 修复建议

```go
// 添加一个无害的额外限制标志
info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
    BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
        LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                    windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    },
}
```

**影响面**: 低，仅 stderr 噪声

---

## Bug 5 🔵 LOW: `--help examples` 在 Release 构建中无输出（待确认）

### ID
BUG-HELP-EXAMPLES-RELEASE

### 现象
Release 版 USBPcapCap.exe `--help examples` 产生空输出。但 Debug 版正常输出 5 行示例。

### 可能根因
待进一步确认。可能是 Release 构建的优化导致 `_stricmp` 或 `getopt_long` 行为差异。代码逻辑无问题。

### 修复建议
- 确认 Release 构建的编译选项是否启用了影响字符串比较的优化
- 添加调试输出到 stderr 确认 `topic` 值

---

## 附: 测试中确认无问题的边界场景

| 场景 | 结果 |
|------|------|
| VID 精确过滤 | ✅ 414 包全部来自目标设备 |
| endpoint 应用层过滤 (EP 0x82) | ✅ 100% 仅含 EP 0x82 |
| transfer-type interrupt 过滤 | ✅ 100% interrupt，无 control/bulk |
| 组合过滤 (endpoint + transfer-type) | ✅ 100% 准确 |
| HID payload 导出与解读 | ✅ 协议格式正确 |
| JSON 输出编码 (UTF-8, 无 BOM) | ✅ |
| PowerShell 管道 | ✅ Start-Process 验证 |
| 路径遍历防护 | ✅ 仅取 basename |
| 并发抓包互斥 | ✅ 返回 CAPTURE_ALREADY_RUNNING |
| 不匹配 VID 的错误响应 | ✅ NO_MATCHED_DEVICE + hint |
| Go 全量测试 (含 race) | ✅ 30/30 PASS |
| C Release 编译 | ✅ 0 警告 |

---

## 回归测试结果 (2026-07-10, 修复后)

使用鼠标 VID=0x1d57 在 USBPcap2 接口上验证：

| 测试 | 结果 |
|------|------|
| immediate 模式 triggered 字段 | ✅ `triggered=true` |
| on-match + 不匹配 endpoint (0x81) | ✅ `triggered=false`, 无文件创建 |
| on-match + 匹配 endpoint (0x82) | ✅ `triggered=true`, 文件创建 15KB |
| stderr 无噪声 | ✅ 无 `invalid write handle` 消息 |

Go 全量测试: ✅ 30/30 PASS (`go test ./... -race`)

---

## 修复优先级建议

| 优先级 | Bug | 修复预估 |
|--------|-----|----------|
| **P0** | BUG-TRIGGERED-FALSE | ~2h (immediate 模式直接设 TRUE；on-match 需线程同步) |
| **P0** | BUG-ONMATCH-WRITES-UNTRIGGERED | ~3h (重构 begin_output_stream 的触发逻辑) |
| **P1** | BUG-INVALID-WRITE-HANDLE | ~1h (提前初始化 write_handle 或抑制输出) |
| **P2** | BUG-JOB-FLAGS | ~0.5h (添加额外标志位) |
| **P3** | BUG-HELP-EXAMPLES-RELEASE | ~1h (调查 Release 编译差异) |
