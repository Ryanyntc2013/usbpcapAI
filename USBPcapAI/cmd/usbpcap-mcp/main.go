// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"usbpcap-ai/internal/ipc"
)

// version is set by ldflags at build time: -X main.version=X.Y.Z
var version = "dev"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      any         `json:"id,omitempty"`
	Result  any         `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type toolCallResult struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "usbpcap_list_interfaces",
			"description": "列出 USBPcap 接口",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "usbpcap_list_devices",
			"description": "列出接口下的已连接 USB 设备",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"interface": map[string]any{"type": "string", "description": "例如 \\\\.\\USBPcap1"},
				},
				"required": []string{"interface"},
			},
		},
		{
			"name":        "usbpcap_probe_device",
			"description": "自动扫描所有 USBPcap 接口，查找匹配 VID/PID 的设备，返回接口和设备地址。AI 优先使用此工具代替 list_interfaces + list_devices。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vendorId":  map[string]any{"type": "string", "description": "例如 0x1a86，也支持 1a86"},
					"productId": map[string]any{"type": "string", "description": "例如 0xffcc，也支持 ffcc"},
				},
			},
		},
		{
			"name":        "usbpcap_smart_capture",
			"description": "高阶工具：自动探测设备 → 选择接口 → 抓包 → 等待完成 → 返回摘要和下一步建议。AI 把此工具作为首选抓包方式。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"interface":       map[string]any{"type": "string", "description": "例如 \\\\.\\USBPcap1，也支持 USBPcap1"},
					"vendorId":        map[string]any{"type": "string", "description": "例如 0x1a86，也支持 1a86"},
					"productId":       map[string]any{"type": "string", "description": "例如 0xffcc，也支持 ffcc"},
					"endpoint":        map[string]any{"type": "string", "description": "例如 0x81，也支持 81"},
					"transferType":    map[string]any{"type": "string", "enum": []string{"control", "bulk", "interrupt", "isochronous", "unknown"}},
					"durationSeconds": map[string]any{"type": "integer", "default": 10},
					"storeMode":       map[string]any{"type": "string", "enum": []string{"immediate", "on-match"}, "default": "immediate"},
				},
			},
		},
		{
			"name":        "usbpcap_capture_once",
			"description": "同步抓包一次并返回 pcap 路径与摘要。短抓包可用，长抓包应改用 startCapture + waitCaptureTask。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"interface":         map[string]any{"type": "string"},
					"autoInterface":     map[string]any{"type": "boolean"},
					"vendorId":          map[string]any{"type": "string", "description": "例如 0x1234"},
					"productId":         map[string]any{"type": "string", "description": "例如 0xabcd"},
					"durationSeconds":   map[string]any{"type": "integer", "minimum": 0},
					"captureNewDevices": map[string]any{"type": "boolean"},
					"appFilter":         map[string]any{"type": "boolean"},
					"endpoint":          map[string]any{"type": "string", "description": "例如 0x81"},
					"transferType":      map[string]any{"type": "string", "enum": []string{"control", "bulk", "interrupt", "isochronous", "unknown"}},
					"storeMode":         map[string]any{"type": "string", "enum": []string{"immediate", "on-match"}},
					"outputFileName":    map[string]any{"type": "string"},
					"idleTimeoutSeconds": map[string]any{"type": "integer", "minimum": 0},
					"maxFileSizeBytes":   map[string]any{"type": "integer", "minimum": 0},
				},
			},
		},
		{
			"name":        "usbpcap_analyze",
			"description": "分析 pcap 文件的 USB 流量，返回端点详情、payload 模式、帧头统计。也支持通过 taskId 直接分析最近抓包。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pcapPath":      map[string]any{"type": "string", "description": "pcap 文件路径"},
					"taskId":        map[string]any{"type": "string", "description": "可选：已完成抓包的 taskId，与 pcapPath 二选一"},
					"deviceAddress": map[string]any{"type": "integer", "description": "可选：仅分析指定设备地址"},
				},
			},
		},
		{
			"name":        "usbpcap_diagnose_capture",
			"description": "诊断为什么抓不到数据，返回结构化诊断结果和下一步建议。AI 在 capture 返回 idle/no_device/no_match 时优先使用此工具。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"taskId":    map[string]any{"type": "string"},
					"vendorId":  map[string]any{"type": "string"},
					"productId": map[string]any{"type": "string"},
				},
				"required": []string{"taskId"},
			},
		},
		{
			"name":        "usbpcap_profile_device",
			"description": "短时间采样设备流量，识别活跃端点、传输类型和 payload 长度分布，并生成推荐抓包配置。AI 在不知道 endpoint 时应先 profile。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vendorId":        map[string]any{"type": "string", "description": "例如 0x1a86"},
					"productId":       map[string]any{"type": "string", "description": "例如 0xffcc"},
					"durationSeconds": map[string]any{"type": "integer", "default": 10},
				},
				"required": []string{"vendorId"},
			},
		},
		{
			"name":        "usbpcap_export_data",
			"description": "从 pcap 提取指定设备和端点的 payload 数据，支持 Hex/CSV/Raw 格式。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pcapPath":      map[string]any{"type": "string"},
					"taskId":        map[string]any{"type": "string", "description": "可选：已完成抓包的 taskId"},
					"deviceAddress": map[string]any{"type": "integer"},
					"endpoint":      map[string]any{"type": "string", "description": "例如 0x81"},
					"format":        map[string]any{"type": "string", "enum": []string{"hex", "csv", "raw"}, "default": "hex"},
					"minDataLen":    map[string]any{"type": "integer", "default": 1},
					"outputFileName": map[string]any{"type": "string", "description": "可选：写入导出目录的文件名"},
				},
				"required": []string{"pcapPath", "endpoint"},
			},
		},
		{
			"name":        "usbpcap_start_capture",
			"description": "异步启动抓包并返回 taskId。之后必须调用 usbpcap_wait_capture_task 等待完成。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"interface":         map[string]any{"type": "string"},
					"autoInterface":     map[string]any{"type": "boolean"},
					"vendorId":          map[string]any{"type": "string", "description": "例如 0x1234"},
					"productId":         map[string]any{"type": "string", "description": "例如 0xabcd"},
					"durationSeconds":   map[string]any{"type": "integer", "minimum": 0},
					"captureNewDevices": map[string]any{"type": "boolean"},
					"appFilter":         map[string]any{"type": "boolean"},
					"endpoint":          map[string]any{"type": "string", "description": "例如 0x81"},
					"transferType":      map[string]any{"type": "string", "enum": []string{"control", "bulk", "interrupt", "isochronous", "unknown"}},
					"storeMode":         map[string]any{"type": "string", "enum": []string{"immediate", "on-match"}},
					"outputFileName":    map[string]any{"type": "string"},
					"idleTimeoutSeconds": map[string]any{"type": "integer", "minimum": 0},
					"maxFileSizeBytes":   map[string]any{"type": "integer", "minimum": 0},
				},
			},
		},
		{
			"name":        "usbpcap_wait_capture_task",
			"description": "等待异步抓包任务完成，返回最终任务状态和 pcap 路径。优先使用此工具代替轮询 get_capture_task。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"taskId":        map[string]any{"type": "string"},
					"timeoutSeconds": map[string]any{"type": "integer", "default": 60},
				},
				"required": []string{"taskId"},
			},
		},
		{
			"name":        "usbpcap_capture_status",
			"description": "查询服务状态与当前抓包状态",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "usbpcap_get_capture_task",
			"description": "按 taskId 查询抓包任务",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"taskId": map[string]any{"type": "string"}}, "required": []string{"taskId"}},
		},
		{
			"name":        "usbpcap_list_capture_tasks",
			"description": "列出当前和最近的抓包任务",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "usbpcap_stop_capture",
			"description": "停止当前正在进行的抓包。支持按 taskId 精确停止正在运行的捕获。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"taskId": map[string]any{"type": "string", "description": "可选：精确停止指定 taskId，不传时停止当前运行的捕获"},
				},
			},
		},
		{
			"name":        "usbpcap_get_config",
			"description": "查询服务当前配置",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "usbpcap_help",
			"description": "查看帮助、过滤语义与示例",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "usbpcap_install_guide",
			"description": "获取 USBPcap MCP 安装指南（驱动安装、服务配置、VS Code 集成）。新用户应首先调用此工具。",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "usbpcap_service_control",
			"description": "管理 USBPcapAIService Windows 服务。status 无需管理员；start/stop/restart 需管理员权限。",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action": map[string]any{
						"type":        "string",
						"enum":        []string{"status", "start", "stop", "restart"},
						"description": "操作: status(查状态), start(启动,需管理员), stop(停止,需管理员), restart(重启,需管理员)",
					},
				},
				"required": []string{"action"},
			},
		},
	}
}

func main() {
	defer ipc.ShutdownService()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for scanner.Scan() {
		line := scanner.Bytes()
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = json.NewEncoder(writer).Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: err.Error()}})
			writer.Flush()
			continue
		}
		// Notifications have no ID — silently accept, do not respond.
		if req.ID == nil {
			handleNotification(req)
			continue
		}
		resp := handle(req)
		_ = json.NewEncoder(writer).Encode(resp)
		writer.Flush()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func handleNotification(req rpcRequest) {
	// Accept notifications/initialized and ping
	switch req.Method {
	case "notifications/initialized":
		// Client is ready — silently accepted per MCP spec.
	default:
		// Other notifications are silently ignored.
	}
}

func handle(req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)
		// Negotiate: if client requests a version we support, echo it.
		// Otherwise respond with our supported version.
		protoVersion := params.ProtocolVersion
		if protoVersion != "2024-11-05" && protoVersion != "2025-03-26" {
			protoVersion = "2024-11-05"
		}
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": protoVersion,
			"serverInfo":      map[string]string{"name": "usbpcap-mcp", "version": version},
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
		}}
	case "tools/list":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": toolDefinitions()}}
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: err.Error()}}
		}
		result, err := callTool(params.Name, params.Arguments)
		if err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32000, Message: err.Error(), Data: map[string]any{"tool": params.Name}}}
		}
		if resp, ok := result.(ipc.Response); ok && !resp.OK {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: wrapToolErrorResult(resp)}
		}
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: wrapToolResult(result)}
	default:
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)}}
	}
}

func wrapToolResult(result any) toolCallResult {
	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		pretty = []byte(fmt.Sprintf("%v", result))
	}
	return toolCallResult{
		Content: []map[string]any{
			{"type": "text", "text": string(pretty)},
		},
	}
}

func wrapToolErrorResult(result any) toolCallResult {
	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		pretty = []byte(fmt.Sprintf("%v", result))
	}
	return toolCallResult{
		IsError: true,
		Content: []map[string]any{
			{"type": "text", "text": string(pretty)},
		},
	}
}

func callTool(name string, raw json.RawMessage) (any, error) {
	switch name {
	case "usbpcap_list_interfaces":
		return ipc.CallWithAutoService(ipc.Request{Action: "listInterfaces"})
	case "usbpcap_list_devices":
		var args struct{ Interface string `json:"interface"` }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return ipc.CallWithAutoService(ipc.Request{Action: "listDevices", Interface: args.Interface})
	case "usbpcap_probe_device":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "probeDevice"
		return ipc.CallWithAutoService(req)
	case "usbpcap_smart_capture":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "smartCapture"
		return ipc.CallWithAutoService(req)
	case "usbpcap_capture_once":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "captureOnce"
		return ipc.CallWithAutoService(req)
	case "usbpcap_start_capture":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "startCapture"
		return ipc.CallWithAutoService(req)
	case "usbpcap_wait_capture_task":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "waitCaptureTask"
		return ipc.CallWithAutoService(req)
	case "usbpcap_analyze":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "analyze"
		return ipc.CallWithAutoService(req)
	case "usbpcap_diagnose_capture":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "diagnoseCapture"
		return ipc.CallWithAutoService(req)
	case "usbpcap_profile_device":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "profileDevice"
		return ipc.CallWithAutoService(req)
	case "usbpcap_export_data":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "exportData"
		return ipc.CallWithAutoService(req)
	case "usbpcap_capture_status":
		return ipc.CallWithAutoService(ipc.Request{Action: "status"})
	case "usbpcap_get_capture_task":
		var args struct{ TaskID string `json:"taskId"` }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return ipc.CallWithAutoService(ipc.Request{Action: "getCaptureTask", TaskID: args.TaskID})
	case "usbpcap_list_capture_tasks":
		return ipc.CallWithAutoService(ipc.Request{Action: "listCaptureTasks"})
	case "usbpcap_stop_capture":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			// If no arguments (empty JSON object or null), ok - stop active
			req = ipc.Request{}
		}
		req.Action = "stopCapture"
		return ipc.CallWithAutoService(req)
	case "usbpcap_get_config":
		return ipc.CallWithAutoService(ipc.Request{Action: "getConfig"})
	case "usbpcap_help":
		return ipc.CallWithAutoService(ipc.Request{Action: "help"})
	case "usbpcap_install_guide":
		return installGuideText(), nil
	case "usbpcap_service_control":
		var ctrl struct{ Action string `json:"action"` }
		if err := json.Unmarshal(raw, &ctrl); err != nil {
			return nil, err
		}
		resp, err := serviceControl(ctrl.Action)
		if err != nil {
			return nil, err
		}
		return resp, nil
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}
