// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"usbpcap-ai/internal/ipc"
	"usbpcap-ai/internal/usbpcapcmd"
)

type fakeRunner struct {
	capture func(context.Context, ipc.Request, string) (*usbpcapcmd.CaptureResult, error)
}

func (f fakeRunner) ListInterfaces() ([]ipc.InterfaceInfo, error) { return nil, nil }
func (f fakeRunner) ListDevices(string) ([]ipc.DeviceInfo, error) { return nil, nil }
func (f fakeRunner) CaptureContext(ctx context.Context, req ipc.Request, path string) (*usbpcapcmd.CaptureResult, error) {
	if f.capture != nil {
		return f.capture(ctx, req, path)
	}
	return &usbpcapcmd.CaptureResult{OK: true, Output: &path, StoreMode: "immediate", Triggered: true}, nil
}

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	cmdPath := filepath.Join(dir, "USBPcapCap.exe")
	if err := os.WriteFile(cmdPath, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig(filepath.Join(dir, "usbpcap-service.exe"))
	cfg.CaptureDir = filepath.Join(dir, "captures")
	cfg.CMDPath = cmdPath
	cfg.IdleTimeoutSeconds = 1
	cfg.MaxFileSizeBytes = 1024
	cfg.MaxHistoryTasks = 5
	cfg.MaxCaptureFiles = 2
	return cfg
}

func TestHandleCaptureValidation(t *testing.T) {
	cfg := testConfig(t)
	srv := NewServer(cfg)
	srv.runner = fakeRunner{}

	resp := srv.handle(ipc.Request{Action: "captureOnce"})
	if resp.OK || resp.ErrorCode != "CAPTURE_TARGET_REQUIRED" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	resp = srv.handle(ipc.Request{Action: "captureOnce", AutoInterface: true})
	if resp.OK || resp.ErrorCode != "AUTO_INTERFACE_FILTER_REQUIRED" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	resp = srv.handle(ipc.Request{Action: "captureOnce", Interface: `\\.\USBPcap1`, StoreMode: "bad"})
	if resp.OK || resp.ErrorCode != "INVALID_STORE_MODE" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	// endpoint + appFilter=false is now auto-fixed by normalizeRequest.
	// The request should be accepted (appFilter auto-enabled), not rejected.
	resp = srv.handle(ipc.Request{Action: "startCapture", Interface: `\\.\USBPcap1`, Endpoint: "0x81"})
	if !resp.OK {
		t.Fatalf("expected endpoint auto-fix to succeed, got: %+v", resp)
	}
	if resp.NormalizedArguments == nil || resp.NormalizedArguments["appFilter"] != true {
		t.Fatalf("expected normalizedArguments.appFilter=true, got %+v", resp.NormalizedArguments)
	}
	// Stop the auto-started capture
	srv.stopCapture("TEST", "test cleanup", "")
}

func TestHandleGetConfigAndStatus(t *testing.T) {
	cfg := testConfig(t)
	srv := NewServer(cfg)

	resp := srv.handle(ipc.Request{Action: "getConfig"})
	if !resp.OK || resp.Config == nil {
		t.Fatalf("unexpected getConfig response: %+v", resp)
	}
	if resp.Config.CMDPath != cfg.CMDPath {
		t.Fatalf("CMDPath=%q, want %q", resp.Config.CMDPath, cfg.CMDPath)
	}

	resp = srv.handle(ipc.Request{Action: "status"})
	if !resp.OK || resp.Config == nil {
		t.Fatalf("unexpected status response: %+v", resp)
	}
}

func TestHandleStatusAndStopCapture(t *testing.T) {
	srv := NewServer(testConfig(t))
	ctxTask := srv.newTask(ipc.Request{Interface: `\\.\USBPcap1`, DurationSeconds: 12, StoreMode: "on-match"}, `E:\captures\a.pcap`)
	ctx, err := srv.beginCapture(ctxTask)
	if err != nil {
		t.Fatal(err)
	}

	resp := srv.handle(ipc.Request{Action: "status"})
	if !resp.OK || resp.ActiveCapture == nil || !resp.ActiveCapture.Running {
		t.Fatalf("unexpected status response: %+v", resp)
	}
	if resp.ActiveCapture.Interface != `\\.\USBPcap1` {
		t.Fatalf("interface=%q, want USBPcap1", resp.ActiveCapture.Interface)
	}

	resp = srv.handle(ipc.Request{Action: "stopCapture"})
	if !resp.OK {
		t.Fatalf("unexpected stop response: %+v", resp)
	}
	select {
	case <-ctx.Done():
		if ctx.Err() != context.Canceled {
			t.Fatalf("ctx err=%v, want canceled", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("expected capture context to be canceled")
	}
	srv.endCapture(ctxTask)

	resp = srv.handle(ipc.Request{Action: "stopCapture"})
	if resp.OK || resp.ErrorCode != "CAPTURE_NOT_RUNNING" {
		t.Fatalf("unexpected stop response after clear: %+v", resp)
	}
}

func TestStartCaptureAndQueryTask(t *testing.T) {
	cfg := testConfig(t)
	srv := NewServer(cfg)
	srv.runner = fakeRunner{capture: func(ctx context.Context, req ipc.Request, path string) (*usbpcapcmd.CaptureResult, error) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte("pcap"), 0o644); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
		return &usbpcapcmd.CaptureResult{OK: true, Output: &path, StoreMode: "immediate", Triggered: true}, nil
	}}

	resp := srv.handle(ipc.Request{Action: "startCapture", Interface: `\\.\USBPcap1`})
	if !resp.OK || resp.Task == nil || resp.Task.TaskID == "" {
		t.Fatalf("unexpected start response: %+v", resp)
	}

	taskResp := srv.handle(ipc.Request{Action: "getCaptureTask", TaskID: resp.Task.TaskID})
	if !taskResp.OK || taskResp.Task == nil {
		t.Fatalf("unexpected task response: %+v", taskResp)
	}

	time.Sleep(100 * time.Millisecond)
	listResp := srv.handle(ipc.Request{Action: "listCaptureTasks"})
	if !listResp.OK || len(listResp.Tasks) == 0 {
		t.Fatalf("unexpected list response: %+v", listResp)
	}
}

func TestBeginCaptureRejectsConcurrentCapture(t *testing.T) {
	srv := NewServer(testConfig(t))
	task := srv.newTask(ipc.Request{Interface: `\\.\USBPcap1`}, `first.pcap`)
	if _, err := srv.beginCapture(task); err != nil {
		t.Fatal(err)
	}
	defer srv.endCapture(task)

	busy := srv.newTask(ipc.Request{Interface: `\\.\USBPcap2`}, `second.pcap`)
	if _, err := srv.beginCapture(busy); err == nil {
		t.Fatal("expected concurrent capture error")
	}
}

func TestNormalizeHexAndInterface(t *testing.T) {
	tests := []struct {
		input    string
		fn       func(string) string
		expected string
	}{

		{"1a86", normalizeHex, "0x1a86"},
		{"0x1a86", normalizeHex, "0x1a86"},
		{"0X1A86", normalizeHex, "0x1a86"},
		{"ffcc", normalizeHex, "0xffcc"},
		{"garbage", normalizeHex, "garbage"}, // invalid hex, return as-is
		{"USBPcap2", normalizeInterface, `\\.\USBPcap2`},
		{`\\.\USBPcap1`, normalizeInterface, `\\.\USBPcap1`},
		{"usbpcap3", normalizeInterface, `\\.\usbpcap3`},
	}
	for _, tt := range tests {
		got := tt.fn(tt.input)
		if got != tt.expected {
			t.Fatalf("%s(%q)=%q, want %q", funcName(tt.fn), tt.input, got, tt.expected)
		}
	}
}

func TestNormalizeRequest(t *testing.T) {
	req := &ipc.Request{
		VendorID:   "1a86",
		ProductID:  "FFCC",
		Endpoint:  "81",
		Interface: "USBPcap2",
	}
	normalized := normalizeRequest(req)
	if req.VendorID != "0x1a86" {
		t.Fatalf("VendorID=%q, want 0x1a86", req.VendorID)
	}
	if req.ProductID != "0xffcc" {
		t.Fatalf("ProductID=%q, want 0xffcc", req.ProductID)
	}
	if req.Endpoint != "0x81" {
		t.Fatalf("Endpoint=%q, want 0x81", req.Endpoint)
	}
	if req.Interface != `\\.\USBPcap2` {
		t.Fatalf("Interface=%q, want \\\\.\\USBPcap2", req.Interface)
	}
	if !req.AppFilter {
		t.Fatal("expected AppFilter to be auto-enabled")
	}
	if _, ok := normalized["vendorId"]; !ok {
		t.Fatal("expected vendorId in normalized")
	}
	if _, ok := normalized["appFilter"]; !ok {
		t.Fatal("expected appFilter in normalized")
	}
}

// TestDefaultOutputPath verifies that outputFileName is properly handled
// (P2-2: custom filenames, path traversal prevention, timestamp fallback).
func TestDefaultOutputPath(t *testing.T) {
	cfg := testConfig(t)
	srv := NewServer(cfg)

	// Custom filename
	path := srv.defaultOutputPath("my-test.pcap")
	expected := filepath.Join(cfg.CaptureDir, "my-test.pcap")
	if path != expected {
		t.Fatalf("defaultOutputPath(%q)=%q, want %q", "my-test.pcap", path, expected)
	}

	// Path traversal prevention
	path = srv.defaultOutputPath("..\\..\\Windows\\evil.pcap")
	expected = filepath.Join(cfg.CaptureDir, "evil.pcap")
	if path != expected {
		t.Fatalf("defaultOutputPath with traversal gave %q, want %q", path, expected)
	}

	// Empty falls back to timestamp
	path = srv.defaultOutputPath("")
	if !strings.HasPrefix(filepath.Base(path), "usbpcap-") {
		t.Fatalf("expected timestamp-based name, got %q", path)
	}

	// Non-pcap extension is preserved
	path = srv.defaultOutputPath("data.bin")
	expected = filepath.Join(cfg.CaptureDir, "data.bin")
	if path != expected {
		t.Fatalf("defaultOutputPath(%q)=%q, want %q", "data.bin", path, expected)
	}
}

func TestHandleAnalyzeWithPCAP(t *testing.T) {
	cfg := testConfig(t)
	srv := NewServer(cfg)

	// Create a minimal valid USBPcap pcap file
	pcapPath := filepath.Join(cfg.CaptureDir, "test.pcap")
	if err := os.MkdirAll(cfg.CaptureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write a minimal pcap. For testing analyze we can just create an empty file
	// since pcap.Analyze is already tested; we're testing the server handler here.
	// Use a real pcap from the summary_test pattern
	file, err := os.Create(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	// Write file header (USBPcap magic + network=249)
	fh := make([]byte, 24)
	writeLE32(fh[0:4], 0xA1B2C3D4) // magic
	writeLE16(fh[4:6], 2)           // major
	writeLE16(fh[6:8], 4)           // minor
	writeLE32(fh[16:20], 65535)     // snaplen
	writeLE32(fh[20:24], 249)       // network = USBPcap
	if _, err := file.Write(fh); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()

	resp := srv.handle(ipc.Request{Action: "analyze", PCAPPath: pcapPath})
	if !resp.OK {
		t.Fatalf("analyze failed: %+v", resp)
	}
	if resp.AnalyzeResult == nil {
		t.Fatal("expected analyzeResult")
	}
}

func TestHandleDiagnoseCaptureTaskNotFound(t *testing.T) {
	srv := NewServer(testConfig(t))
	resp := srv.handle(ipc.Request{Action: "diagnoseCapture", TaskID: "nonexistent"})
	if resp.OK || resp.Status != "task_not_found" {
		t.Fatalf("expected task_not_found, got: %+v", resp)
	}
}

func TestHandleDiagnoseCaptureNoDevice(t *testing.T) {
	srv := NewServer(testConfig(t))
	task := srv.newTask(ipc.Request{Interface: `\\.\USBPcap1`}, "test.pcap")
	task.task.Status = "no_device"
	task.task.ErrorCode = "NO_MATCHED_DEVICE"
	srv.registerTask(task)
	srv.recordHistory(task.task)

	resp := srv.handle(ipc.Request{Action: "diagnoseCapture", TaskID: task.task.TaskID})
	if !resp.OK {
		t.Fatalf("unexpected error: %+v", resp)
	}
	if resp.DiagnosisResult == nil || resp.DiagnosisResult.Diagnosis != "NO_DEVICE" {
		t.Fatalf("expected NO_DEVICE, got %+v", resp.DiagnosisResult)
	}
}

func TestHandleDiagnoseCaptureIdle(t *testing.T) {
	srv := NewServer(testConfig(t))
	task := srv.newTask(ipc.Request{Interface: `\\.\USBPcap1`}, "test.pcap")
	task.task.Status = "idle"
	task.task.Summary = &ipc.Summary{PacketCount: 0}
	srv.registerTask(task)
	srv.recordHistory(task.task)

	resp := srv.handle(ipc.Request{Action: "diagnoseCapture", TaskID: task.task.TaskID})
	if !resp.OK {
		t.Fatalf("unexpected error: %+v", resp)
	}
	if resp.DiagnosisResult == nil || resp.DiagnosisResult.Diagnosis != "DEVICE_IDLE" {
		t.Fatalf("expected DEVICE_IDLE, got %+v", resp.DiagnosisResult)
	}
}

func TestHandleExportDataFailsWithoutEndpoint(t *testing.T) {
	srv := NewServer(testConfig(t))
	// Use a path within capture dir but with empty endpoint
	pcapPath := filepath.Join(srv.cfg.CaptureDir, "test.pcap")
	resp := srv.handle(ipc.Request{Action: "exportData", PCAPPath: pcapPath})
	if resp.OK || resp.ErrorCode != "ENDPOINT_REQUIRED" {
		t.Fatalf("expected ENDPOINT_REQUIRED, got: %+v", resp)
	}
}

// Helpers for binary encoding in tests
func writeLE32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
func writeLE16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

// funcName returns a name for a function value for test output
func funcName(f any) string {
	return "func"
}
