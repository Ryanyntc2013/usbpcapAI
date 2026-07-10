// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package usbpcapcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"usbpcap-ai/internal/ipc"
)

type Runner struct {
	CMDPath string
}

type CaptureResult struct {
	OK             bool                `json:"ok"`
	ErrorCode      string              `json:"errorCode,omitempty"`
	Message        string              `json:"message,omitempty"`
	Hint           string              `json:"hint,omitempty"`
	Output         *string             `json:"output,omitempty"`
	Triggered      bool                `json:"triggered,omitempty"`
	StoreMode      string              `json:"storeMode,omitempty"`
	DroppedPackets uint64              `json:"droppedPackets,omitempty"`
	Interfaces     []ipc.InterfaceInfo `json:"interfaces,omitempty"`
	Devices        []ipc.DeviceInfo    `json:"devices,omitempty"`
	MatchedDevices []ipc.MatchedDevice `json:"matchedDevices,omitempty"`
	Reason         string              `json:"reason,omitempty"`
}

// CmdError represents a structured error returned by USBPcapCMD in JSON.
// It preserves the original errorCode/message/hint from the C-side output.
type CmdError struct {
	ErrorCode string
	Message   string
	Hint      string
}

func (e *CmdError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("[%s] %s", e.ErrorCode, e.Message)
	}
	return fmt.Sprintf("[%s]", e.ErrorCode)
}

func (r Runner) ListInterfaces() ([]ipc.InterfaceInfo, error) {
	out, err := r.run("--list-interfaces", "--json", "--no-interactive")
	if err != nil {
		return nil, err
	}
	var resp CaptureResult
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	return resp.Interfaces, nil
}

func (r Runner) ListDevices(iface string) ([]ipc.DeviceInfo, error) {
	out, err := r.run("--list-devices", "--device", iface, "--json", "--no-interactive")
	if err != nil {
		return nil, err
	}
	var resp CaptureResult
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	// Populate AddressHex from Address
	for i := range resp.Devices {
		resp.Devices[i].AddressHex = fmt.Sprintf("0x%04x", resp.Devices[i].Address)
	}
	return resp.Devices, nil
}

func (r Runner) Capture(req ipc.Request, outputPath string) (*CaptureResult, error) {
	return r.CaptureContext(context.Background(), req, outputPath)
}

// buildCaptureArgs constructs the CLI arguments for USBPcapCap.
// It is exported for testing.
func BuildCaptureArgs(req ipc.Request, outputPath string) []string {
	args := []string{"--json", "--no-interactive", "--output", outputPath}
	if req.Interface != "" {
		args = append(args, "--device", req.Interface)
	}
	if req.AutoInterface {
		args = append(args, "--auto-interface")
	}
	if req.VendorID != "" {
		args = append(args, "--vendor-id", req.VendorID)
	}
	if req.ProductID != "" {
		args = append(args, "--product-id", req.ProductID)
	}
	if req.DurationSeconds > 0 {
		args = append(args, "--duration", fmt.Sprintf("%d", req.DurationSeconds))
	}
	if req.CaptureNewDevices {
		args = append(args, "--capture-from-new-devices")
	}
	// -A enables driver-level capture of all devices on the interface.
	// Only add -A when no VID/PID filter is active — VID/PID filtering
	// resolves to an address list for precise driver-level address filtering.
	// Adding -A with VID/PID would override the resolved address list
	// and capture unrelated devices, violating the design requirement.
	if !req.CaptureNewDevices && req.VendorID == "" && req.ProductID == "" {
		args = append(args, "-A")
	}
	if req.AppFilter {
		args = append(args, "--app-filter")
	}
	if req.Endpoint != "" {
		args = append(args, "--endpoint", req.Endpoint)
	}
	if req.TransferType != "" {
		args = append(args, "--transfer-type", req.TransferType)
	}
	if req.StoreMode != "" {
		args = append(args, "--store-mode", req.StoreMode)
	}
	return args
}

func (r Runner) CaptureContext(ctx context.Context, req ipc.Request, outputPath string) (*CaptureResult, error) {
	args := BuildCaptureArgs(req, outputPath)
	out, err := r.runContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	var resp CaptureResult
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, &CmdError{
			ErrorCode: resp.ErrorCode,
			Message:   resp.Message,
			Hint:      resp.Hint,
		}
	}
	return &resp, nil
}

func (r Runner) run(args ...string) ([]byte, error) {
	return r.runContext(context.Background(), args...)
}

func (r Runner) runContext(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.CMDPath, args...)
	cmd.Dir = filepath.Dir(r.CMDPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %q failed: %w", strings.Join(args, " "), err)
	}

	// Assign child process to a kill-on-close job so that if the service
	// crashes or is terminated the child will not outlive it.
	job, err := windows.CreateJobObject(nil, nil)
	if err == nil {
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, jErr := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); jErr != nil {
			windows.CloseHandle(job)
			job = 0
		}
		if job != 0 {
			procHandle, pErr := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
				false, uint32(cmd.Process.Pid))
			if pErr == nil {
				_ = windows.AssignProcessToJobObject(job, procHandle)
				windows.CloseHandle(procHandle)
			} else {
				windows.CloseHandle(job)
				job = 0
			}
		}
	}

	// Keep the job handle alive until the child exits.
	defer func() {
		if job != 0 {
			windows.CloseHandle(job)
		}
	}()

	err = cmd.Wait()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Try to parse stdout as structured JSON error first.
		// C outputs JSON errors to stdout even on non-zero exit.
		if stdout.Len() > 0 {
			var cr CaptureResult
			if jsonErr := json.Unmarshal(stdout.Bytes(), &cr); jsonErr == nil && !cr.OK {
				return nil, &CmdError{
					ErrorCode: cr.ErrorCode,
					Message:   cr.Message,
					Hint:      cr.Hint,
				}
			}
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("run %q failed: %s", strings.Join(args, " "), msg)
	}
	return stdout.Bytes(), nil
}
