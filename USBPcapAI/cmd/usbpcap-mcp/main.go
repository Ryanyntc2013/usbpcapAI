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
			"name":        "usbpcap_capture_once",
			"description": "抓包一次并返回 pcap 路径与摘要",
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
			"name":        "usbpcap_start_capture",
			"description": "异步启动抓包并返回 taskId",
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
			"description": "停止当前正在进行的抓包",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
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
	}
}

func main() {
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
		resp := handle(req)
		_ = json.NewEncoder(writer).Encode(resp)
		writer.Flush()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func handle(req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]string{"name": "usbpcap-mcp", "version": "0.1.0"},
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
			{"type": "json", "json": result},
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
			{"type": "json", "json": result},
		},
	}
}

func callTool(name string, raw json.RawMessage) (any, error) {
	switch name {
	case "usbpcap_list_interfaces":
		return ipc.Call(ipc.Request{Action: "listInterfaces"})
	case "usbpcap_list_devices":
		var args struct{ Interface string `json:"interface"` }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return ipc.Call(ipc.Request{Action: "listDevices", Interface: args.Interface})
	case "usbpcap_capture_once":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "captureOnce"
		return ipc.Call(req)
	case "usbpcap_start_capture":
		var req ipc.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		req.Action = "startCapture"
		return ipc.Call(req)
	case "usbpcap_capture_status":
		return ipc.Call(ipc.Request{Action: "status"})
	case "usbpcap_get_capture_task":
		var args struct{ TaskID string `json:"taskId"` }
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return ipc.Call(ipc.Request{Action: "getCaptureTask", TaskID: args.TaskID})
	case "usbpcap_list_capture_tasks":
		return ipc.Call(ipc.Request{Action: "listCaptureTasks"})
	case "usbpcap_stop_capture":
		return ipc.Call(ipc.Request{Action: "stopCapture"})
	case "usbpcap_get_config":
		return ipc.Call(ipc.Request{Action: "getConfig"})
	case "usbpcap_help":
		return ipc.Call(ipc.Request{Action: "help"})
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}
