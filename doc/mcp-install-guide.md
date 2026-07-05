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

> **无需管理员权限即可使用！** MCP 自动按需启动/停止服务。

---

## 三、快速上手（免管理员）

### 3.1 解压

```powershell
Expand-Archive usbpcap-mcp-vX.Y.Z.zip -DestinationPath "C:\USBPcapMCP"
```

### 3.2 安装驱动（仅一次，需管理员）

```powershell
bcdedit /set testsigning on     # 启用测试签名（重启生效）
# 重启后：
cd C:\USBPcapMCP
.\USBPcapService.exe driver-install
```

### 3.3 配置 VS Code MCP

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

### 3.4 开始使用

直接调用 MCP 工具（如 `usbpcap_list_interfaces`），MCP 自动启动服务。

> **工作原理**：USBPcapMCP.exe 首次调用工具时自动以 `USBPcapService.exe run` 启动服务；MCP 退出时自动停止。全程无需管理员。

---

## 四、可选：安装为 Windows 服务（开机自启，需管理员）

```powershell
.\USBPcapService.exe install
.\USBPcapService.exe start
```

---

## 五、所有管理命令（USBPcapService.exe）

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

## 六、验证

1. 在 VS Code 中调用 MCP 工具 `usbpcap_list_interfaces`
2. 或命令行验证驱动：`.\USBPcapCap.exe --list-interfaces`

---

## 七、故障排查

| 症状 | 排查 |
|------|------|
| MCP 连接失败 | 确认 USBPcapService.exe 与 USBPcapMCP.exe 在同一目录 |
| 抓包无数据 | 检查驱动是否安装，测试签名是否启用 |
| bcdedit 报错 | 以管理员运行 PowerShell |
| 驱动安装失败 | 关闭 Secure Boot 或启用测试签名 |
| 权限错误 | 驱动/服务安装需管理员；日常使用无需 |
