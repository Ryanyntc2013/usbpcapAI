// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package ipc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

// ServiceLauncher manages auto-launching the service process
// when the Windows service is not installed or not running.
type ServiceLauncher struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	job      uintptr // kill-on-close job handle (Windows only)
	launched bool
}

var globalLauncher = &ServiceLauncher{}

// EnsureService checks if the pipe is available. If not, it launches
// USBPcapService.exe run from the same directory as the MCP binary.
func EnsureService() error {
	return globalLauncher.EnsureService()
}

// ShutdownService kills the auto-launched service process if any.
func ShutdownService() {
	globalLauncher.Shutdown()
}

func (l *ServiceLauncher) EnsureService() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.launched {
		return nil
	}
	l.launched = true

	// Fast check: pipe already available (could be Windows service or previous run instance)
	if l.pipeAvailable(500 * time.Millisecond) {
		return nil
	}

	// Discover service exe path (same dir as MCP)
	mcpExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate MCP executable: %w", err)
	}
	svcPath := filepath.Join(filepath.Dir(mcpExe), "USBPcapService.exe")

	if _, err := os.Stat(svcPath); os.IsNotExist(err) {
		return fmt.Errorf("USBPcapService.exe not found at %s -- place it alongside USBPcapMCP.exe", svcPath)
	}

	// Launch service in foreground mode (no admin required)
	l.cmd = exec.Command(svcPath, "run")
	l.cmd.Stdout = os.Stdout
	l.cmd.Stderr = os.Stderr

	if err := l.cmd.Start(); err != nil {
		l.launched = false
		return fmt.Errorf("failed to launch service: %w", err)
	}

	// Assign to kill-on-close job so the child dies when MCP exits
	if j, err := assignToKillOnCloseJob(l.cmd.Process.Pid); err == nil {
		l.job = uintptr(j)
	}

	// Wait for pipe to become available
	if !l.pipeAvailable(15 * time.Second) {
		l.killProcess()
		l.launched = false
		return fmt.Errorf("service did not become ready within 15 seconds")
	}

	return nil
}

func (l *ServiceLauncher) pipeAvailable(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := winio.DialPipeContext(context.Background(), PipeName)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func (l *ServiceLauncher) killProcess() {
	if l.cmd != nil && l.cmd.Process != nil {
		l.cmd.Process.Kill()
		_ = l.cmd.Wait()
		l.cmd = nil
	}
}

func (l *ServiceLauncher) Shutdown() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.killProcess()
	l.launched = false
}
