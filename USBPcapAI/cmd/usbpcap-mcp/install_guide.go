// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// installGuideText returns the full installation guide as a tool result.
func installGuideText() map[string]any {
	return map[string]any{
		"guide": installGuideMarkdown,
	}
}

// serviceControl executes USBPcapService.exe commands for Windows service management.
func serviceControl(action string) (map[string]any, error) {
	mcpExe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	svcPath := filepath.Join(filepath.Dir(mcpExe), "USBPcapService.exe")
	if _, err := os.Stat(svcPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("USBPcapService.exe not found alongside USBPcapMCP.exe")
	}

	var out []byte
	switch action {
	case "status":
		out, err = exec.Command(svcPath, "status").CombinedOutput()
	case "start", "stop", "restart":
		out, err = exec.Command(svcPath, action).CombinedOutput()
	default:
		return nil, fmt.Errorf("unknown action: %s (use status/start/stop/restart)", action)
	}
	return map[string]any{
		"action": action,
		"output": strings.TrimSpace(string(out)),
		"error":  fmt.Sprintf("%v", err),
		"note":   "start/stop/restart require Administrator privileges. If you get 'access denied', run PowerShell as Administrator and use: USBPcapService.exe " + action,
	}, nil
}

var installGuideMarkdown = `# USBPcap MCP 安装指南

## 一、快速上手（免管理员）

### 1. 解压发布包
将 usbpcap-mcp-vX.Y.Z.zip 解压到任意目录，例如 C:\USBPcapMCP。

### 2. 安装 USBPcap 驱动（仅一次，需管理员）
以管理员身份运行 PowerShell：
  bcdedit /set testsigning on
  （重启电脑）
  cd C:\USBPcapMCP
  .\USBPcapService.exe driver-install

### 3. 配置 VS Code MCP
在 .vscode/mcp.json 中添加：
  {
    "servers": {
      "usbpcap": {
        "type": "stdio",
        "command": "C:\\USBPcapMCP\\USBPcapMCP.exe",
        "args": []
      }
    }
  }

### 4. 开始使用
直接调用 MCP 工具即可，服务会自动启动，无需额外操作。

## 二、可选：安装为 Windows 服务（开机自启，需管理员）
  cd C:\USBPcapMCP
  .\USBPcapService.exe install
  .\USBPcapService.exe start

## 三、所有管理命令（USBPcapService.exe）
  USBPcapService.exe help                    # 帮助
  USBPcapService.exe version                # 版本
  USBPcapService.exe status                 # 服务状态（无需管理员）
  USBPcapService.exe run                    # 前台运行（MCP 自动使用）
  USBPcapService.exe driver-install         # 安装驱动（需管理员）
  USBPcapService.exe driver-uninstall       # 卸载驱动（需管理员）
  USBPcapService.exe install                # 安装为 Windows 服务（需管理员）
  USBPcapService.exe uninstall              # 卸载服务（需管理员）
  USBPcapService.exe start                  # 启动服务（需管理员）
  USBPcapService.exe stop                   # 停止服务（需管理员）
  USBPcapService.exe restart                # 重启服务（需管理员）

## 四、故障排查
- MCP 连接失败：确认 USBPcapService.exe 与 USBPcapMCP.exe 在同一目录
- 抓包无数据：检查驱动是否已安装，测试签名是否启用
- 权限错误：安装驱动/服务需要管理员；日常使用 MCP 无需管理员
- 驱动安装失败：确认 Secure Boot 已关闭，或启用测试签名（bcdedit /set testsigning on）`
