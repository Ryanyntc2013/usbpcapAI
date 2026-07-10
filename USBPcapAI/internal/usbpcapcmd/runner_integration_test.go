// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package usbpcapcmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"usbpcap-ai/internal/ipc"
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

func TestBuildCaptureArgs(t *testing.T) {
	tests := []struct {
		name     string
		req      ipc.Request
		contains []string
		excludes []string
	}{
		{
			name:     "bare interface",
			req:      ipc.Request{Interface: `\\.\USBPcap1`},
			contains: []string{"--device", `\\.\USBPcap1`, "-A"},
			excludes: []string{"--vendor-id", "--product-id", "--capture-from-new-devices"},
		},
		{
			name:     "with VID filter",
			req:      ipc.Request{Interface: `\\.\USBPcap1`, VendorID: "0x1234"},
			contains: []string{"--vendor-id", "0x1234"},
			excludes: []string{"-A"},
		},
		{
			name:     "with VID+PID filter",
			req:      ipc.Request{Interface: `\\.\USBPcap1`, VendorID: "0x1234", ProductID: "0xabcd"},
			contains: []string{"--vendor-id", "0x1234", "--product-id", "0xabcd"},
			excludes: []string{"-A"},
		},
		{
			name:     "captureNewDevices excludes -A",
			req:      ipc.Request{Interface: `\\.\USBPcap1`, CaptureNewDevices: true},
			contains: []string{"--capture-from-new-devices"},
			excludes: []string{"-A"},
		},
		{
			name:     "captureNewDevices with VID",
			req:      ipc.Request{Interface: `\\.\USBPcap1`, VendorID: "0x1234", CaptureNewDevices: true},
			contains: []string{"--vendor-id", "--capture-from-new-devices"},
			excludes: []string{"-A"},
		},
		{
			name:     "app filter with endpoint",
			req:      ipc.Request{Interface: `\\.\USBPcap1`, AppFilter: true, Endpoint: "0x81"},
			contains: []string{"--app-filter", "--endpoint", "0x81", "-A"},
		},
		{
			name:     "on-match store mode",
			req:      ipc.Request{Interface: `\\.\USBPcap1`, StoreMode: "on-match"},
			contains: []string{"--store-mode", "on-match", "-A"},
		},
		{
			name:     "auto interface",
			req:      ipc.Request{AutoInterface: true, VendorID: "0x1234"},
			contains: []string{"--auto-interface", "--vendor-id"},
			excludes: []string{"-A"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := BuildCaptureArgs(tt.req, "out.pcap")
			argStr := " " + strings.Join(args, " ") + " "
			for _, c := range tt.contains {
				if !strings.Contains(argStr, " "+c+" ") && !strings.HasSuffix(argStr, " "+c+" ") {
					// also check as prefix of a longer arg
					found := false
					for _, a := range args {
						if a == c {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected arg %q in %v", c, args)
					}
				}
			}
			for _, e := range tt.excludes {
				found := false
				for _, a := range args {
					if a == e {
						found = true
						break
					}
				}
				if found {
					t.Errorf("unexpected arg %q in %v", e, args)
				}
			}
		})
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
