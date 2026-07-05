# USBPcapMCP 修复记录

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
