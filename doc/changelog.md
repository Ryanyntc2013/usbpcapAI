# USBPcapMCP 修复记录

## 2026-07-10 — v0.4.0

### 正确性与安全修复

**P0-1: VID/PID 过滤参数修复**
- 提取 `BuildCaptureArgs()` 纯函数，有 VID/PID 时不加 `-A`
- 防止 `-A` 覆盖地址列表导致精确过滤失效

**P0-2: 结构化错误链路**
- Runner 在非零退出时先解析 stdout JSON，成功则返回 `CmdError`
- `NO_MATCHED_DEVICE` 等状态可稳定传递到 Service 层

**P0-3~5: 统一 PCAP Reader + 分析修复**
- 新增 `pcap.Reader` / `OpenReader()`：单记录 64MiB 上限、越界 payload 安全截断
- `Analyze()`: `PacketCount` 修正为真实包数，endpoint key 加入 device 防合并，结果稳定排序
- `ExportPayload()`: 使用安全 Reader，10000 包 / 64MiB 总上限
- `Summarize()`: 复用 `SummarizeReader()`

**P0-6: safePcapPath 加固**
- `filepath.Rel` 防前缀绕过，`Lstat` 拒绝 symlink/junction
- `handleAnalyze` 统一复用 `safePcapPath()`

**P0-7: Service 可取消生命周期**
- 新增 `ListenAndServeContext(ctx)`，取消时关闭 listener
- SCM Stop 主动取消 + 10s 等待优雅停止
- `shutdown()` 停止活动抓包后返回

**P0-8: MCP 协议合规**
- `initialize` 读取客户端版本并协商
- Notification 不产生响应
- ToolResult 移除非标准 `content.type:"json"`

**P0-9: Pipe ACL 收紧**
- SDDL 从全部 `IU` 改为当前进程用户 SID

### 稳定性修复

**P1: 任务并发安全**
- `captureTaskState.taskMu` + `updateTaskSnapshot()`/`taskSnapshot()` 消除 data race
- `go test -race ./...` 全通过

**P1: 状态统一**
- `no-match` → `no_match` 全部统一

**P1: 输出文件**
- `defaultOutputPath()` 强制追加 `.pcap` 后缀

### 文档同步
- README: 工具数 10→19，补全工具表，双模式权限说明
- improvement-roadmap: 标记已实现项目
- mcp-install-guide: 修正双模式权限描述，删除重复故障条目

---

## 2026-07-05 — v0.3.0

### Breaking: USBPcapCMD.exe 重命名为 USBPcapCap.exe

**原因**: 本项目从社区开源 `USBPcapCMD` 改造而来，为与旧项目名称做出明确区分，将可执行文件重命名为 `USBPcapCap.exe`（"Cap" = Capture）。

**影响范围**:
- CMake target: `USBPcapCMD` → `USBPcapCap`
- C 源码帮助文本、资源文件 OriginalFilename
- Go 代码中所有 `.exe` 引用、配置校验、错误提示
- PowerShell/Batch 构建部署脚本
- VS Code tasks.json 任务标签
- NSIS/WiX 安装器
- 所有文档（README、changelog、设计文档、安装指南）

**兼容性**: Service 默认 `config.json` 中 `cmdPath` 指向同目录 `USBPcapCap.exe`，老配置需手动更新 `cmdPath` 字段。

---

## 2026-07-05 — v0.1.1

### Bug 1: VID/PID 过滤导致抓包失败

**严重程度**: 🔴 CRITICAL  
**文件**: `USBPcapAI/internal/usbpcapcmd/runner.go`

**现象**:
- `start_capture(interface, vendorId=0x1a86)` → `exit status 0xffffffff`
- `capture_once(autoInterface=true, vendorId=0x1a86, productId=0xffcc)` → `empty capture`

**根因**: VID/PID 非空时不加 `-A`。USBPcapCMD 中 VID/PID 仅设置 `app_filter`，不填充 `address_list`。capture_thread sanity check `capture_all || address_list != NULL` 失败。

**修复**: 移除 VID/PID 为空的条件检查。只要不是 `captureNewDevices` 都加 `-A`。

```diff
- if !req.CaptureNewDevices && strings.TrimSpace(req.VendorID) == "" && strings.TrimSpace(req.ProductID) == "" {
+ // Always add -A. VID/PID filtering is app-layer after capture.
+ if !req.CaptureNewDevices {
```

**验证**: `start_capture(interface="\\.\USBPcap2", vendorId="0x1a86")` → `completed, matchedDevices: [address:16]`

---

### Bug 2: Summary 统计全错（USBPcap 头偏移量错误）

**严重程度**: 🔴 CRITICAL  
**文件**: `USBPcapAI/internal/pcap/summary.go` + `summary_test.go`

**现象**:

| 字段 | 修复前 (错误) | 修复后 (正确) |
|------|-------------|-------------|
| deviceDistribution | `{"0x02": 74}` | `{"0x10": 66, "0x11": 8}` |
| endpointDistribution | `{"0x10": 66, "0x11": 8}` | `{"0x02": 28, "0x80": 8, "0x81": 38}` |
| transferTypes | `{"isochronous": 74}` | `{"bulk": 66, "control": 8}` |

**根因**: USBPcap 头 (27 bytes) 中 Device/Endpoint/Transfer 字段偏移量全错 2 字节：
- 正确: `Device @19, Endpoint @21, Transfer @22`
- 错误: `Device @17 (Bus), Endpoint @19 (Device[0]), Transfer @20 (Device[1])`

**修复**: 三行改动 + 测试同步

```diff
- uh.Device = binary.LittleEndian.Uint16(buf[17:19])
- uh.Endpoint = buf[19]
- uh.Transfer = buf[20]
+ uh.Device = binary.LittleEndian.Uint16(buf[19:21])
+ uh.Endpoint = buf[21]
+ uh.Transfer = buf[22]
```

**验证**: tshark 交叉确认一致，`go test ./...` 全部通过 (5 packages)。

---

### 部署修复

- `config.json` cmdPath → `E:\test\usbpcap\output\release\USBPcapCap.exe`
- Windows 服务 `USBPcapAIService` 重装指向 release 二进制
- `USBPcapService.exe` + `USBPcapMCP.exe` 重新编译 → `output/release/`
