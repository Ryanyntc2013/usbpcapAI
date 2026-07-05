// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package usbpcapcmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func findCMDExe(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "out", "build", "vs2022-x64-debug", "bin", "Debug", "USBPcapCap.exe"),
		filepath.Join("..", "..", "out", "build", "vs2022-x64-debug", "bin", "Debug", "USBPcapCap.exe"),
	}
	for _, rel := range candidates {
		abs, err := filepath.Abs(rel)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("USBPcapCap.exe not found; build it first with cmake --build --preset build-debug")
	return ""
}

func TestCLIListInterfacesValidJSON(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("USBPcapCMD only runs on Windows")
	}
	exe := findCMDExe(t)

	r := Runner{CMDPath: exe}
	raw, err := r.run("--list-interfaces", "--json", "--no-interactive")
	if err != nil {
		t.Fatalf("--list-interfaces failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty JSON output from --list-interfaces")
	}
	var parsed CaptureResult
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("--list-interfaces output is not valid JSON: %v\n%s", err, string(raw))
	}
	// Interfaces may be empty when no driver is present; that is valid.
	if parsed.Interfaces == nil {
		t.Fatalf("expected interfaces array in JSON: %s", string(raw))
	}
}

func TestCLIListAllDevicesValidJSON(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("USBPcapCMD only runs on Windows")
	}
	exe := findCMDExe(t)

	r := Runner{CMDPath: exe}
	raw, err := r.run("--list-devices", "--json", "--no-interactive")
	if err != nil {
		t.Fatalf("--list-devices failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty JSON output from --list-devices")
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("--list-devices output is not valid JSON: %v\n%s", err, string(raw))
	}
	if _, ok := parsed["interfaces"]; !ok {
		t.Fatalf("expected 'interfaces' key in JSON: %s", string(raw))
	}
}

func TestCLIHelpProducesText(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("USBPcapCMD only runs on Windows")
	}
	exe := findCMDExe(t)

	r := Runner{CMDPath: exe}
	raw, err := r.run("--help")
	if err != nil {
		t.Fatalf("--help failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty help output")
	}
}
