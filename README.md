# USBPcap — Windows USB 抓包工具（AI 增强版）

[![License](https://img.shields.io/badge/license-BSD--2--Clause%20%2F%20GPLv2-blue)](LICENSE)

**USBPcap** 是一款面向 Windows 平台的 USB 数据包捕获工具，基于 [Tomasz Moń 原始项目](http://desowin.org/usbpcap) 演进而来。

本仓库在原有驱动和命令行工具之上，新增了 **USBPcapAI** 模块 —— 一个专为 AI 工具设计的 MCP 服务器 + Windows 服务层，使 USB 抓包能力可以无缝被 AI 编程助手（如 Claude、Copilot 等）调用。

---

## 项目结构

```
usbpcap/
├── USBPcapDriver/          # 内核过滤驱动 (GPLv2)
├── USBPcapCMD/             # 用户态命令行抓包工具 (BSD-2-Clause)
├── USBPcapAI/              # Go 实现的 AI 抓包服务层 (BSD-2-Clause)
│   ├── cmd/usbpcap-mcp/    #   MCP 服务器 — 供 AI 工具通过 stdio JSON-RPC 调用
│   └── cmd/usbpcap-service/ #   Windows Service — 以高权限运行，免除 UAC 弹窗
└── captures/               # 抓包输出目录
```

## 核心特性

### 传统能力
- 基于 Windows 内核过滤驱动实现 USB 数据包捕获
- 输出标准 **pcap/pcapng** 格式，兼容 Wireshark 分析
- 支持按 USB 地址过滤设备

### USBPcapAI 新增能力
| 特性 | 说明 |
|------|------|
| 🤖 **MCP 协议支持** | 通过标准 stdio JSON-RPC 为 AI 工具暴露 19 个 MCP 工具 |
| 🔌 **VID/PID 精确过滤** | 已连接设备可按 Vendor ID / Product ID 精准匹配 |
| 🎯 **Endpoint 过滤** | 支持按端点地址（如 `0x81`）过滤 |
| 📦 **传输类型过滤** | 支持 `control` / `bulk` / `interrupt` / `isochronous` |
| 🔔 **触发式存储** | 命中匹配条件后才开始写盘，适合长时间监测 |
| ⏱️ **长期监测保护** | 空闲超时、文件大小上限、自动清理旧文件 |
| 🪟 **双模式部署** | Windows Service 模式真正免 UAC；MCP 前台模式免安装便携使用 |
| 📊 **抓包摘要** | 自动返回 pcap 文件路径、端点统计和流量概要 |
| 🗂️ **异步任务与历史** | 支持异步启动抓包并返回 `taskId`，可查询历史 |
| 🪝 **新设备自动捕获** | 可选择捕获抓包期间新插入的任意 USB 设备 |
| 🔍 **智能探测** | `probe_device` 自动跨接口扫描设备，无需手动指定 interface |
| 🧠 **一键抓包** | `smart_capture` 探测→抓包→等待→摘要→建议下一步，一步完成 |
| 📈 **流量分析** | `analyze` 按端点/传输类型/payload 模式分析 pcap |
| 🩺 **故障诊断** | `diagnose_capture` 结构化诊断空包/空闲/过滤过严等原因 |
| 📤 **数据导出** | `export_data` 从 pcap 提取 payload（Hex/CSV/Raw） |
| ⏳ **显式等待** | `wait_capture_task` 阻塞等待异步任务完成，适合 AI agent 调用 |

### MCP 工具列表

| 工具名 | 功能 |
|--------|------|
| `usbpcap_list_interfaces` | 列出可用的 USBPcap 捕获接口 |
| `usbpcap_list_devices` | 列出指定接口下已连接的 USB 设备 |
| `usbpcap_probe_device` | 自动扫描所有接口，按 VID/PID 定位设备 |
| `usbpcap_smart_capture` | 一键完成探测→抓包→等待→摘要 |
| `usbpcap_capture_once` | 执行一次同步抓包并返回 pcap 路径与摘要 |
| `usbpcap_start_capture` | 异步启动抓包并返回 `taskId` |
| `usbpcap_wait_capture_task` | 阻塞等待异步任务完成，返回完整结果 |
| `usbpcap_get_capture_task` | 按 `taskId` 查询抓包任务状态与结果 |
| `usbpcap_list_capture_tasks` | 列出当前和最近的抓包任务 |
| `usbpcap_capture_status` | 查询抓包服务运行状态 |
| `usbpcap_stop_capture` | 停止当前正在进行的抓包（支持按 taskId） |
| `usbpcap_analyze` | 分析 pcap 的端点详情、payload 模式和帧统计 |
| `usbpcap_profile_device` | 短采样识别活跃端点并生成推荐配置 |
| `usbpcap_diagnose_capture` | 结构化诊断空包/空闲/过滤过严等原因 |
| `usbpcap_export_data` | 从 pcap 提取 payload（Hex/CSV/Raw） |
| `usbpcap_get_config` | 查看服务当前配置 |
| `usbpcap_help` | 查看帮助、过滤语义与使用示例 |
| `usbpcap_install_guide` | 获取安装指南 |
| `usbpcap_service_control` | 管理 Windows 服务状态 |

## 快速开始

### 前置条件
- Windows 10/11 x64
- 启用测试签名模式：`Bcdedit.exe -set TESTSIGNING ON` 并重启
- [Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### 构建

```powershell
# 1. 构建 USBPcapCap（CMake）
cmake --preset vs2022-x64-debug
cmake --build --preset build-debug

# 2. 构建 USBPcapAI（Go）
cd USBPcapAI
go build -o ../out/build/vs2022-x64-debug/bin/Debug/USBPcapMCP.exe ./cmd/usbpcap-mcp/
go build -o ../out/build/vs2022-x64-debug/bin/Debug/USBPcapService.exe ./cmd/usbpcap-service/
```

### 安装与运行

```powershell
# 安装 Windows 服务（以管理员身份运行）
USBPcapService.exe install --capture-dir .\captures

# 启动服务
USBPcapService.exe start

# MCP 客户端可直接通过 stdio 调用 USBPcapMCP.exe
```

### MCP 配置示例（Claude Desktop / VS Code Copilot）

```json
{
  "mcpServers": {
    "usbpcap": {
      "command": "USBPcapMCP.exe",
      "args": []
    }
  }
}
```

## 许可证

本仓库采用**分层许可证**结构：

| 模块 | 许可证 | 版权 |
|------|--------|------|
| `USBPcapDriver/` | [GPLv2](nsis/gpl-2.0.txt) | © 2013-2020 Tomasz Moń |
| `USBPcapCMD/` | [BSD 2-Clause](nsis/bsd-2clause.txt) | © 2013-2018 Tomasz Moń |
| `USBPcapAI/` | [BSD 2-Clause](USBPcapAI/LICENSE) | © 2026 Ryanyntc2013 |

## 致谢

本项目基于 Tomasz Moń 的 [USBPcap](http://desowin.org/usbpcap) 原始项目构建，感谢原作者对 USB 抓包社区的贡献。

---

# USBPcap — USB Packet Capture for Windows (AI-Enhanced)

[![License](https://img.shields.io/badge/license-BSD--2--Clause%20%2F%20GPLv2-blue)](LICENSE)

**USBPcap** is a USB packet capture tool for Windows, evolved from the [original project by Tomasz Moń](http://desowin.org/usbpcap).

On top of the existing kernel driver and CLI tool, this repository introduces **USBPcapAI** — an MCP server + Windows service layer purpose-built for AI tooling, enabling USB packet capture to be seamlessly invoked by AI coding assistants like Claude, Copilot, and others.

---

## Project Structure

```
usbpcap/
├── USBPcapDriver/          # Kernel filter driver (GPLv2)
├── USBPcapCMD/             # User-space capture CLI (BSD-2-Clause)
├── USBPcapAI/              # Go-based AI capture service layer (BSD-2-Clause)
│   ├── cmd/usbpcap-mcp/    #   MCP server — stdio JSON-RPC for AI tools
│   └── cmd/usbpcap-service/ #   Windows Service — elevated capture, no UAC prompts
└── captures/               # Capture output directory
```

## Key Features

### Classic Capabilities
- USB packet capture via Windows kernel filter driver
- Output in standard **pcap/pcapng** format, compatible with Wireshark
- Filter by USB device address

### USBPcapAI Enhancements
| Feature | Description |
|---------|-------------|
| 🤖 **MCP Protocol** | Exposes 19 MCP tools to AI agents via stdio JSON-RPC |
| 🔌 **VID/PID Filtering** | Precise filtering by Vendor ID / Product ID for connected devices |
| 🎯 **Endpoint Filtering** | Filter by endpoint address (e.g. `0x81`) |
| 📦 **Transfer Type Filtering** | Support for `control` / `bulk` / `interrupt` / `isochronous` |
| 🔔 **Triggered Capture** | Start writing to disk only on condition match |
| ⏱️ **Capture Limits** | Idle timeout, file size cap, automatic old-file cleanup |
| 🪟 **Dual-Mode** | Windows Service for true zero-UAC; MCP foreground mode for portable use |
| 📊 **Capture Summary** | Auto-returns pcap file path, endpoint stats, and traffic overview |
| 🗂️ **Async Tasks & History** | `startCapture` returns `taskId`; query current and recent history |
| 🪝 **New Device Capture** | Optionally capture any USB device plugged in during the session |
| 🔍 **Smart Probing** | `probe_device` scans all interfaces automatically by VID/PID |
| 🧠 **One-Click Capture** | `smart_capture`: probe→capture→wait→summary in one step |
| 📈 **Traffic Analysis** | `analyze` breaks down endpoints, transfer types, and payload patterns |
| 🩺 **Diagnosis** | `diagnose_capture` provides structured diagnosis for empty/failed captures |
| 📤 **Data Export** | `export_data` extracts payload as Hex/CSV/Raw from pcap |
| ⏳ **Explicit Wait** | `wait_capture_task` blocks until async capture completes |

### MCP Tools

| Tool | Description |
|------|-------------|
| `usbpcap_list_interfaces` | List available USBPcap capture interfaces |
| `usbpcap_list_devices` | List connected USB devices on a given interface |
| `usbpcap_probe_device` | Auto-scan all interfaces by VID/PID to locate a device |
| `usbpcap_smart_capture` | One-click probe→capture→wait→summary→next step |
| `usbpcap_capture_once` | Perform a single synchronous capture, return pcap path + summary |
| `usbpcap_start_capture` | Start an async capture and return `taskId` |
| `usbpcap_wait_capture_task` | Block until async capture completes, return full results |
| `usbpcap_get_capture_task` | Query capture task status and results by `taskId` |
| `usbpcap_list_capture_tasks` | List current and recent capture tasks |
| `usbpcap_capture_status` | Query capture service status |
| `usbpcap_stop_capture` | Stop the currently running capture (by taskId) |
| `usbpcap_analyze` | Analyze pcap: endpoint details, payload patterns, frame stats |
| `usbpcap_profile_device` | Short sample to discover active endpoints, recommend config |
| `usbpcap_diagnose_capture` | Structured diagnosis for empty/idle/filtered captures |
| `usbpcap_export_data` | Extract payload from pcap in Hex/CSV/Raw |
| `usbpcap_get_config` | View current service configuration |
| `usbpcap_help` | Show help, filter semantics, and usage examples |
| `usbpcap_install_guide` | Get installation guide |
| `usbpcap_service_control` | Manage Windows service status |

## Quick Start

### Prerequisites
- Windows 10/11 x64
- Enable test signing: `Bcdedit.exe -set TESTSIGNING ON` (reboot required)
- [Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### Build

```powershell
# 1. Build USBPcapCap (CMake)
cmake --preset vs2022-x64-debug
cmake --build --preset build-debug

# 2. Build USBPcapAI (Go)
cd USBPcapAI
go build -o ../out/build/vs2022-x64-debug/bin/Debug/USBPcapMCP.exe ./cmd/usbpcap-mcp/
go build -o ../out/build/vs2022-x64-debug/bin/Debug/USBPcapService.exe ./cmd/usbpcap-service/
```

### Install & Run

```powershell
# Install the Windows Service (run as Administrator)
USBPcapService.exe install --capture-dir .\captures

# Start the service
USBPcapService.exe start

# MCP clients invoke USBPcapMCP.exe directly over stdio
```

### MCP Configuration (Claude Desktop / VS Code Copilot)

```json
{
  "mcpServers": {
    "usbpcap": {
      "command": "USBPcapMCP.exe",
      "args": []
    }
  }
}
```

## License

This repository uses a **layered license** structure:

| Module | License | Copyright |
|--------|---------|-----------|
| `USBPcapDriver/` | [GPLv2](nsis/gpl-2.0.txt) | © 2013-2020 Tomasz Moń |
| `USBPcapCMD/` | [BSD 2-Clause](nsis/bsd-2clause.txt) | © 2013-2018 Tomasz Moń |
| `USBPcapAI/` | [BSD 2-Clause](USBPcapAI/LICENSE) | © 2026 Ryanyntc2013 |

## Acknowledgments

Built upon Tomasz Moń's original [USBPcap](http://desowin.org/usbpcap) project. Grateful for the author's contributions to the USB capture community.
