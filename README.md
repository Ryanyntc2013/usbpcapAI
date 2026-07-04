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
| 🤖 **MCP 协议支持** | 通过标准 stdio JSON-RPC 为 AI 工具暴露 10 个抓包工具 |
| 🔌 **VID/PID 精确过滤** | 已连接设备可按 Vendor ID / Product ID 精准匹配 |
| 🎯 **Endpoint 过滤** | 支持按端点地址（如 `0x81`）过滤 |
| 📦 **传输类型过滤** | 支持 `control` / `bulk` / `interrupt` / `isochronous` |
| 🔔 **触发式存储** | 命中匹配条件后才开始写盘，适合长时间监测 |
| ⏱️ **长期监测保护** | 空闲超时 (`idleTimeout`)、文件大小上限 (`maxFileSize`)、自动清理旧抓包文件 |
| 🪟 **无 UAC 弹窗** | 以后台 Windows Service 运行抓包，AI 调用流畅无阻断 |
| 📊 **抓包摘要** | 自动返回 pcap 文件路径、端点统计和流量概要 |
| 🗂️ **异步任务与历史** | 支持异步启动抓包并返回 `taskId`，可查询当前和最近的抓包历史 |
| 🪝 **新设备自动捕获** | 可选择捕获抓包期间新插入的任意 USB 设备 |

### MCP 工具列表

| 工具名 | 功能 |
|--------|------|
| `usbpcap_list_interfaces` | 列出可用的 USBPcap 捕获接口 |
| `usbpcap_list_devices` | 列出指定接口下已连接的 USB 设备 |
| `usbpcap_capture_once` | 执行一次同步抓包并返回 pcap 路径与摘要 |
| `usbpcap_start_capture` | 异步启动抓包并返回 `taskId` |
| `usbpcap_get_capture_task` | 按 `taskId` 查询抓包任务状态与结果 |
| `usbpcap_list_capture_tasks` | 列出当前和最近的抓包任务 |
| `usbpcap_capture_status` | 查询抓包服务运行状态 |
| `usbpcap_stop_capture` | 停止当前正在进行的抓包 |
| `usbpcap_get_config` | 查看服务当前配置（含保护参数） |
| `usbpcap_help` | 查看帮助、过滤语义与使用示例 |

## 快速开始

### 前置条件
- Windows 10/11 x64
- 启用测试签名模式：`Bcdedit.exe -set TESTSIGNING ON` 并重启
- [Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### 构建

```powershell
# 1. 构建 USBPcapCMD（CMake）
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
| 🤖 **MCP Protocol** | Exposes 10 capture tools to AI agents via stdio JSON-RPC |
| 🔌 **VID/PID Filtering** | Precise filtering by Vendor ID / Product ID for connected devices |
| 🎯 **Endpoint Filtering** | Filter by endpoint address (e.g. `0x81`) |
| 📦 **Transfer Type Filtering** | Support for `control` / `bulk` / `interrupt` / `isochronous` |
| 🔔 **Triggered Capture** | Start writing to disk only on condition match — ideal for long-duration monitoring |
| ⏱️ **Capture Limits** | Idle timeout (`idleTimeout`), file size cap (`maxFileSize`), and automatic old-file cleanup |
| 🪟 **Zero UAC Prompts** | Capture runs as a background Windows Service; frictionless AI invocation |
| 📊 **Capture Summary** | Auto-returns pcap file path, endpoint stats, and traffic overview |
| 🗂️ **Async Tasks & History** | `startCapture` returns `taskId` immediately; query current and recent capture history |
| 🪝 **New Device Capture** | Optionally capture any USB device plugged in during the session |

### MCP Tools

| Tool | Description |
|------|-------------|
| `usbpcap_list_interfaces` | List available USBPcap capture interfaces |
| `usbpcap_list_devices` | List connected USB devices on a given interface |
| `usbpcap_capture_once` | Perform a single synchronous capture and return pcap path + summary |
| `usbpcap_start_capture` | Start an async capture and return `taskId` immediately |
| `usbpcap_get_capture_task` | Query capture task status and results by `taskId` |
| `usbpcap_list_capture_tasks` | List current and recent capture tasks |
| `usbpcap_capture_status` | Query capture service status |
| `usbpcap_stop_capture` | Stop the currently running capture |
| `usbpcap_get_config` | View current service configuration (including protection parameters) |
| `usbpcap_help` | Show help, filter semantics, and usage examples |

## Quick Start

### Prerequisites
- Windows 10/11 x64
- Enable test signing: `Bcdedit.exe -set TESTSIGNING ON` (reboot required)
- [Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### Build

```powershell
# 1. Build USBPcapCMD (CMake)
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
