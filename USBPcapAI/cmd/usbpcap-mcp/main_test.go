// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import "testing"

func TestToolDefinitionsIncludeConfigAndStop(t *testing.T) {
	defs := toolDefinitions()
	foundConfig := false
	foundStop := false
	foundStart := false
	foundGetTask := false
	for _, def := range defs {
		if def["name"] == "usbpcap_get_config" {
			foundConfig = true
		}
		if def["name"] == "usbpcap_stop_capture" {
			foundStop = true
		}
		if def["name"] == "usbpcap_start_capture" {
			foundStart = true
		}
		if def["name"] == "usbpcap_get_capture_task" {
			foundGetTask = true
		}
	}
	if !foundConfig {
		t.Fatal("usbpcap_get_config not found")
	}
	if !foundStop {
		t.Fatal("usbpcap_stop_capture not found")
	}
	if !foundStart {
		t.Fatal("usbpcap_start_capture not found")
	}
	if !foundGetTask {
		t.Fatal("usbpcap_get_capture_task not found")
	}
}

func TestWrapToolResult(t *testing.T) {
	result := wrapToolResult(map[string]any{"ok": true, "value": 1})
	if len(result.Content) != 2 {
		t.Fatalf("content length=%d, want 2", len(result.Content))
	}
	if result.Content[0]["type"] != "text" {
		t.Fatalf("first content type=%v", result.Content[0]["type"])
	}
	if result.Content[1]["type"] != "json" {
		t.Fatalf("second content type=%v", result.Content[1]["type"])
	}
}
