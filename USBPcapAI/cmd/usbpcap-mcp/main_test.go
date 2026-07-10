// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import "testing"

func TestToolDefinitionsIncludeAll(t *testing.T) {
	defs := toolDefinitions()
	names := make(map[string]bool)
	for _, def := range defs {
		name, _ := def["name"].(string)
		names[name] = true
	}
	required := []string{
		"usbpcap_get_config", "usbpcap_stop_capture", "usbpcap_start_capture",
		"usbpcap_get_capture_task", "usbpcap_probe_device", "usbpcap_smart_capture",
		"usbpcap_wait_capture_task", "usbpcap_list_interfaces", "usbpcap_list_devices",
		"usbpcap_capture_once", "usbpcap_capture_status", "usbpcap_list_capture_tasks",
		"usbpcap_help", "usbpcap_analyze", "usbpcap_diagnose_capture",
		"usbpcap_profile_device", "usbpcap_export_data",
		"usbpcap_install_guide", "usbpcap_service_control",
	}
	for _, name := range required {
		if !names[name] {
			t.Fatalf("required tool %q not found", name)
		}
	}
	if len(defs) < 16 {
		t.Fatalf("expected at least 14 tool definitions, got %d", len(defs))
	}
}

func TestWrapToolResult(t *testing.T) {
	result := wrapToolResult(map[string]any{"ok": true, "value": 1})
	if len(result.Content) != 1 {
		t.Fatalf("content length=%d, want 1", len(result.Content))
	}
	if result.Content[0]["type"] != "text" {
		t.Fatalf("first content type=%v", result.Content[0]["type"])
	}
}
