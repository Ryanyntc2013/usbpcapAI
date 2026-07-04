// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package service

import (
	"context"
	"os"
	"path/filepath"
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
	cmdPath := filepath.Join(dir, "USBPcapCMD.exe")
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
	srv := NewServer(testConfig(t))

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

	resp = srv.handle(ipc.Request{Action: "captureOnce", Interface: `\\.\USBPcap1`, AppFilter: false, Endpoint: "0x81"})
	if resp.OK || resp.ErrorCode != "APP_FILTER_REQUIRED" {
		t.Fatalf("unexpected response: %+v", resp)
	}
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
