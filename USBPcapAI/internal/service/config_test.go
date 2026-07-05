// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadConfig(t *testing.T) {
	dir := t.TempDir()
	exePath := filepath.Join(dir, "usbpcap-service.exe")
	cmdPath := filepath.Join(dir, "USBPcapCap.exe")
	if err := os.WriteFile(cmdPath, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig(exePath)
	cfg.CaptureDir = filepath.Join(dir, "captures")
	cfg.CMDPath = cmdPath
	if err := SaveConfig(exePath, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(exePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CaptureDir != cfg.CaptureDir {
		t.Fatalf("CaptureDir=%q, want %q", loaded.CaptureDir, cfg.CaptureDir)
	}
	if loaded.CMDPath != cfg.CMDPath {
		t.Fatalf("CMDPath=%q, want %q", loaded.CMDPath, cfg.CMDPath)
	}
}

func TestValidateCreatesCaptureDir(t *testing.T) {
	dir := t.TempDir()
	cmdPath := filepath.Join(dir, "USBPcapCap.exe")
	if err := os.WriteFile(cmdPath, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig(filepath.Join(dir, "usbpcap-service.exe"))
	cfg.CaptureDir = filepath.Join(dir, "nested", "captures")
	cfg.CMDPath = cmdPath
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := filepath.Dir(cfg.CaptureDir); got == "" {
		t.Fatal("expected capture dir path")
	}
}

func TestValidateRejectsRelativeOrMissingCMDPath(t *testing.T) {
	cfg := DefaultConfig(filepath.Join(t.TempDir(), "usbpcap-service.exe"))
	cfg.CaptureDir = t.TempDir()
	cfg.CMDPath = `USBPcapCap.exe`
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected relative cmd path validation error")
	}

	wrongName := filepath.Join(t.TempDir(), "other.exe")
	if err := os.WriteFile(wrongName, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg = DefaultConfig(filepath.Join(t.TempDir(), "usbpcap-service.exe"))
	cfg.CaptureDir = t.TempDir()
	cfg.CMDPath = wrongName
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected wrong filename validation error")
	}

	cfg = DefaultConfig(filepath.Join(t.TempDir(), "usbpcap-service.exe"))
	cfg.CaptureDir = t.TempDir()
	cfg.CMDPath = filepath.Join(t.TempDir(), "missing.exe")
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing cmd path validation error")
	}
}
