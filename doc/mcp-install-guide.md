# USBPcap MCP — 安装与配置指南

> 版本：请参见 `VERSION` 文件  
> 适用平台：Windows x64

---

## 一、发布包内容

```
usbpcap-mcp-vX.Y.Z/
├── USBPcapCap.exe        # C 驱动层抓包命令行工具
├── USBPcapMCP.exe         # MCP Server（stdio/jsonrpc）
├── USBPcapService.exe     # 服务端（所有管理功能统一入口）
├── mcp-install-guide.md   # 本文档
├── VERSION                # 版本号
├── drivers/               # USBPcap 驱动文件（按 OS 版本/架构分层）
└── captures/              # 抓包输出目录（空）
```

---

## 二、前置条件

1. **USBPcap 驱动** — 见下方
2. **64 位 Windows 需关闭 Secure Boot 或启用测试签名**
3. **VS Code**（用于配置 MCP 客户端）

> **两种运行模式**:
> - **MCP 前台模式**: MCP 首次调用时自动启动服务，MCP 退出时自动停止。便携免安装，但驱动访问可能需提权。
> - **Windows Service 模式**: 首次 `install` + `start` 需管理员；之后后台运行，真正免 UAC，适合长期使用。
>
> 两种模式互斥，详见第五节。

---

## 三、快速上手（免管理员）

### 3.1 选择模式

| 模式 | 首次操作 | 日常使用 | 适合场景 |
|------|---------|---------|---------|
| MCP 前台（默认） | 解压即可用 | 调用工具时自动启动服务 | 开发调试、临时抓包 |
| Windows Service | `install` + `start`（需管理员） | 无需管理员，后台常驻 | 长期监测、开机自启 |

### 3.2 解压

```powershell
Expand-Archive usbpcap-mcp-vX.Y.Z.zip -DestinationPath "C:\USBPcapMCP"
```

### 3.3 安装驱动（仅一次，需管理员）

```powershell
bcdedit /set testsigning on     # 启用测试签名（重启生效）
# 重启后：
cd C:\USBPcapMCP
.\USBPcapService.exe driver-install
```

### 3.4 配置 VS Code MCP

在 `.vscode/mcp.json` 中添加：

```json
{
  "servers": {
    "usbpcap": {
      "type": "stdio",
      "command": "C:\\USBPcapMCP\\USBPcapMCP.exe",
      "args": []
    }
  }
}
```

### 3.5 开始使用

直接调用 MCP 工具（如 `usbpcap_list_interfaces`），MCP 自动启动前台服务。

> **工作原理**：USBPcapMCP.exe 首次调用工具时自动以 `USBPcapService.exe run` 启动前台服务；
> MCP 退出时自动停止。前台模式无需安装，但若驱动权限不足时需以管理员身份运行。

---

## 四、可选：安装为 Windows 服务（开机自启，需管理员）

```powershell
.\USBPcapService.exe install
.\USBPcapService.exe start
```

---

## ⚠ 五、重要：两种运行模式互斥

USBPcapService 的 **前台模式**（`run`）和 **Windows 服务模式**（`start`/SCM 自启）**不能同时使用**。

### 为什么？

两种模式使用同一个命名管道 `\\.\pipe\usbpcap-ai-service` 进行 IPC 通信。Named pipe 是独占资源——同一时间只能有一个进程持有。第二个启动的进程会失败退出。

### 具体表现

| 场景 | 结果 |
|------|------|
| Windows 服务运行中 → MCP 自动启动前台模式 | ❌ 前台模式报错 `Access is denied` |
| 前台模式运行中 → `USBPcapService.exe start` | ❌ 服务立即退出（Event ID 7023） |
| 干净环境 → 启动任意一种模式 | ✅ 正常运行 |

### 如何选择

| 使用场景 | 推荐模式 | 操作 |
|----------|---------|------|
| 日常开发 / AI 调用 | 前台模式（MCP 自动管理） | 无需额外操作 |
| 7×24 后台抓包、开机自启 | Windows 服务模式 | `install` + `start` |
| 需要不登录后台运行 | Windows 服务模式 | `install` + `start`（设为 Automatic） |

### 切换模式前

在切换前，确保另一种模式已停止：

```powershell
# 停止 Windows 服务（如果要改用 MCP 前台模式）
USBPcapService.exe stop

# 或关闭 MCP 所在的 VS Code 终端（如果要改用 Windows 服务模式）
```

---

## 六、所有管理命令（USBPcapService.exe）

| 命令 | 说明 | 需管理员 |
|------|------|---------|
| `USBPcapService.exe help` | 显示帮助 | 否 |
| `USBPcapService.exe version` | 显示版本 | 否 |
| `USBPcapService.exe status` | 查看服务状态 | 否 |
| `USBPcapService.exe run` | 前台运行（MCP 自动调用） | 否 |
| `USBPcapService.exe driver-install` | 安装 USBPcap 驱动 | 是 |
| `USBPcapService.exe driver-uninstall` | 卸载 USBPcap 驱动 | 是 |
| `USBPcapService.exe install` | 安装为 Windows 服务 | 是 |
| `USBPcapService.exe uninstall` | 卸载 Windows 服务 | 是 |
| `USBPcapService.exe start` | 启动服务 | 是 |
| `USBPcapService.exe stop` | 停止服务 | 是 |
| `USBPcapService.exe restart` | 重启服务 | 是 |

---

## 七、验证

1. 在 VS Code 中调用 MCP 工具 `usbpcap_list_interfaces`
2. 或命令行验证驱动：`.\USBPcapCap.exe --list-interfaces`

---

## 八、故障排查

| 症状 | 排查 |
|------|------|
| MCP 连接失败 | 确认 USBPcapService.exe 与 USBPcapMCP.exe 在同一目录 |
| 命名管道冲突：服务启动后立即退出（Event ID 7023）或前台 run 报 `Access is denied` | 另一个实例已占用管道。详见[第五节：两种运行模式互斥](#⚠-五重要两种运行模式互斥) |
| 抓包无数据 | 检查驱动是否安装，测试签名是否启用 |
| `bcdedit` 报错 | 以管理员运行 PowerShell |
| 驱动安装失败 | 关闭 Secure Boot 或启用测试签名 |
| 权限错误 | 驱动/服务安装需管理员；MCP 前台模式可能需以管理员运行才能访问驱动 |
| Windows Event Log 中有 `USBPcapAIService failed` 错误 | 服务启动时 `ListenAndServe` 失败，查看日志详情判断是否是管道冲突 |
