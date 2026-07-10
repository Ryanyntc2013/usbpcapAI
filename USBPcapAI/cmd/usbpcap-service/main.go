// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"usbpcap-ai/internal/service"
)

// version is set by ldflags at build time: -X main.version=X.Y.Z
var version = "dev"

const (
	serviceName           = "USBPcapAIService"
	singleInstanceMutexName = "Global\\USBPcapAIService"
)

type serviceProgram struct {
	cfg  service.Config
	elog *eventlog.Log
}

func (m *serviceProgram) logError(msg string) {
	if m.elog != nil {
		m.elog.Error(1, msg)
	}
}

func (m *serviceProgram) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := service.NewServer(m.cfg)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeContext(ctx)
	}()

	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				// Wait for the server to finish with a timeout
				select {
				case <-errCh:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case err := <-errCh:
			if err != nil {
				msg := fmt.Sprintf("USBPcapAIService failed: %v\n\nPossible cause: Another instance (foreground 'run' mode or another service) is already holding the named pipe \\\\.\\pipe\\usbpcap-ai-service. Only one instance can use the pipe at a time.", err)
				m.logError(msg)
				return false, 1
			}
			return false, 0
		}
	}
}

func main() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg, err := service.LoadConfig(exePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(os.Args) > 1 {
		switch strings.ToLower(os.Args[1]) {
		case "run":
			checkSingleInstance()
			must(service.NewServer(cfg).ListenAndServe())
			return
		case "install":
			cfg = applyConfigArgs(cfg, os.Args[2:])
			// Auto-generate config defaults if not specified
			if cfg.CaptureDir == "" {
				cfg.CaptureDir = filepath.Join(filepath.Dir(exePath), "captures")
			}
			if cfg.CMDPath == "" {
				cfg.CMDPath = filepath.Join(filepath.Dir(exePath), "USBPcapCap.exe")
			}
			os.MkdirAll(cfg.CaptureDir, 0755)
			must(validateInstallLocation(exePath, cfg))
			must(cfg.Validate())
			must(service.SaveConfig(exePath, cfg))
			fmt.Printf("  Generated config.json (captureDir=%s)\n", cfg.CaptureDir)
			must(installService(exePath))
			fmt.Println("Service installed successfully. Use 'start' to start.")
			return
		case "configure":
			cfg = applyConfigArgs(cfg, os.Args[2:])
			must(validateInstallLocation(exePath, cfg))
			must(cfg.Validate())
			must(service.SaveConfig(exePath, cfg))
			fmt.Printf("saved config to %s\n", service.ConfigPath(exePath))
			return
		case "uninstall":
			must(uninstallService())
			return
		case "start":
			must(controlService("start"))
			return
		case "stop":
			must(controlService("stop"))
			return
		case "restart":
			must(controlService("stop"))
			must(controlService("start"))
			fmt.Println("Service restarted.")
			return
		case "status":
			must(printStatus(cfg))
			return
		case "driver-install":
			must(driverInstall(exePath))
			return
		case "driver-uninstall":
			must(driverUninstall(exePath))
			return
		case "version", "--version", "-v":
			fmt.Printf("USBPcapService version %s\n", version)
			return
		case "help", "-h", "--help":
			printHelp()
			return
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
			printHelp()
			os.Exit(1)
		}
	}

	// No args: if running as Windows service, enter SCM loop; otherwise show help
	isService, err := svc.IsWindowsService()
	if err == nil && isService {
		checkSingleInstance()
		// Try to open Windows Event Log for error reporting.
		// eventlog.Open works for any source name — Windows auto-creates
		// an entry under the Application log if none is pre-registered.
		var elog *eventlog.Log
		if e, err := eventlog.Open(serviceName); err == nil {
			elog = e
			defer e.Close()
		}
		prog := &serviceProgram{cfg: cfg, elog: elog}
		must(svc.Run(serviceName, prog))
		return
	}
	// Not a Windows service and no args — print help
	printHelp()
}

func installService(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service already installed")
	}
	_, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceName,
		Description: "USBPcap AI local capture service",
		StartType:   mgr.StartAutomatic,
	})
	return err
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Delete()
}

func controlService(action string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if action == "start" {
		return s.Start()
	}
	_, err = s.Control(svc.Stop)
	return err
}

func serviceStateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", state)
	}
}

func printStatus(cfg service.Config) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", serviceName, serviceStateName(st.State))
	fmt.Printf("cmd: %s\n", cfg.CMDPath)
	fmt.Printf("captures: %s\n", cfg.CaptureDir)
	fmt.Printf("config: %s\n", service.ConfigPath(mustExecutable()))
	return nil
}

func applyConfigArgs(cfg service.Config, args []string) service.Config {
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "--capture-dir":
			if i+1 < len(args) {
				cfg.CaptureDir = args[i+1]
				i++
			}
		case "--cmd-path":
			if i+1 < len(args) {
				cfg.CMDPath = args[i+1]
				i++
			}
		case "--idle-timeout-seconds":
			if i+1 < len(args) {
				if v, err := strconv.ParseUint(args[i+1], 10, 32); err == nil {
					cfg.IdleTimeoutSeconds = uint32(v)
				}
				i++
			}
		case "--max-file-size-bytes":
			if i+1 < len(args) {
				if v, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					cfg.MaxFileSizeBytes = v
				}
				i++
			}
		case "--max-history-tasks":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					cfg.MaxHistoryTasks = v
				}
				i++
			}
		case "--max-capture-files":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					cfg.MaxCaptureFiles = v
				}
				i++
			}
		}
	}

	if cfg.CaptureDir != "" && !filepath.IsAbs(cfg.CaptureDir) {
		cfg.CaptureDir = filepath.Join(filepath.Dir(mustExecutable()), cfg.CaptureDir)
	}
	if cfg.CMDPath != "" && !filepath.IsAbs(cfg.CMDPath) {
		cfg.CMDPath = filepath.Join(filepath.Dir(mustExecutable()), cfg.CMDPath)
	}
	return cfg
}

func printHelp() {
	fmt.Print(`
USBPcapService — USBPcap AI capture service

Usage:
  USBPcapService.exe [command]

Commands:
  run                 Run in foreground (used by MCP auto-launch)
  install             Install as Windows service (admin) — auto-generates config
  uninstall           Uninstall Windows service (admin)
  start               Start Windows service (admin)
  stop                Stop Windows service (admin)
  restart             Restart Windows service (admin)
  status              Show service status
  configure           Save config.json
  driver-install      Install USBPcap driver (admin)
  driver-uninstall    Uninstall USBPcap driver (admin)
  version             Show version
  help                Show this help

Auto-launch mode (default, no admin required):
  USBPcapMCP.exe automatically starts USBPcapService.exe run when needed
  and stops it when the MCP exits — no admin required.

⚠ IMPORTANT: Foreground mode and Windows service mode are MUTUALLY EXCLUSIVE.
  • Do NOT run 'USBPcapService.exe run' while the service is installed and
    running, and vice versa.
  • Both modes share the same named pipe (\\.\pipe\usbpcap-ai-service)
    and only one process can hold it at a time.
  • If you need the Windows service, stop/disable the MCP auto-launch first.
  • If you use MCP auto-launch, ensure the Windows service is stopped.

Examples:
  USBPcapService.exe run                    # foreground mode (MCP auto-launch)
  USBPcapService.exe install                # install + auto-config
  USBPcapService.exe install --capture-dir "D:\caps"
  USBPcapService.exe driver-install
  USBPcapService.exe status
`)
}

func validateInstallLocation(exePath string, cfg service.Config) error {
	tempDir := strings.ToLower(filepath.Clean(os.TempDir()))
	paths := []string{filepath.Dir(exePath), cfg.CMDPath, cfg.CaptureDir}
	for _, p := range paths {
		clean := strings.ToLower(filepath.Clean(p))
		if clean == tempDir || strings.HasPrefix(clean, tempDir+string(os.PathSeparator)) {
			return fmt.Errorf("refusing to install service using temporary path: %s", p)
		}
	}
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func mustExecutable() string {
	p, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return p
}

// checkSingleInstance creates a named Windows mutex to prevent multiple
// USBPcapService processes from running simultaneously. Only one instance
// (foreground "run" mode or SCM service) can hold the named pipe at a time.
func checkSingleInstance() {
	mutex, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(singleInstanceMutexName))
	if err == windows.ERROR_ALREADY_EXISTS {
		// Another instance is already holding the mutex.
		fmt.Fprint(os.Stderr, `
ERROR: Another instance of USBPcapService is already running.

  USBPcapService uses a single named pipe (\\.\pipe\usbpcap-ai-service)
  that can only be held by one process at a time.

  Possible causes:
    • A foreground 'USBPcapService.exe run' is already running (e.g. from
      an active VS Code / MCP session that auto-launched it).
    • The Windows service "USBPcapAIService" is currently running
      (check with: sc.exe query USBPcapAIService).

  To resolve:
    1. Identify and stop the other instance.
    2. If the Windows service is running, use:
         USBPcapService.exe stop
    3. Or close the VS Code / MCP session that launched the foreground mode.

  WARNING: Foreground mode and Windows service mode are mutually exclusive.
  Use only one at a time.
`)
		os.Exit(1)
	}
	if err != nil {
		// Unexpected error — log a warning but let the process continue.
		fmt.Fprintf(os.Stderr, "Warning: could not create instance mutex: %v\n", err)
		return
	}
	// First instance: the mutex handle is held until process exit.
	// Leak the handle intentionally — Windows releases it on process termination.
	_ = mutex
}
