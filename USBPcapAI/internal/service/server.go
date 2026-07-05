// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Microsoft/go-winio"

	"usbpcap-ai/internal/ipc"
	"usbpcap-ai/internal/pcap"
	"usbpcap-ai/internal/usbpcapcmd"
)

const defaultCaptureDurationSeconds uint32 = 10
const localPipeSecurityDescriptor = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

type commandRunner interface {
	ListInterfaces() ([]ipc.InterfaceInfo, error)
	ListDevices(string) ([]ipc.DeviceInfo, error)
	CaptureContext(context.Context, ipc.Request, string) (*usbpcapcmd.CaptureResult, error)
}

type Server struct {
	cfg        Config
	startedAt  time.Time
	runner     commandRunner
	mu         sync.Mutex
	active     *activeCapture
	tasks      map[string]*captureTaskState
	history    []ipc.CaptureTask
	nextTaskID uint64
}

type activeCapture struct {
	taskID        string
	interfaceName string
	outputPath    string
	storeMode     string
	durationSec   uint32
	startedAt     time.Time
	cancel        context.CancelFunc
}

type captureTaskState struct {
	task     ipc.CaptureTask
	req      ipc.Request
	cancel   context.CancelFunc
	stopCode string
	stopMsg  string
	stopHint string
	done     chan struct{}
}

func NewServer(cfg Config) *Server {
	return &Server{
		cfg:       cfg,
		startedAt: time.Now(),
		runner:    usbpcapcmd.Runner{CMDPath: cfg.CMDPath},
		tasks:     make(map[string]*captureTaskState),
	}
}

func (s *Server) ListenAndServe() error {
	if err := s.cfg.Validate(); err != nil {
		return err
	}
	_ = os.Remove(ipc.PipeName)
	ln, err := winio.ListenPipe(ipc.PipeName, &winio.PipeConfig{
		InputBufferSize:   64 * 1024,
		OutputBufferSize:  64 * 1024,
		SecurityDescriptor: localPipeSecurityDescriptor,
	})
	if err != nil {
		return err
	}
	defer ln.Close()

	// Start periodic history cleanup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.startHistoryCleanup(ctx)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	defer writer.Flush()

	var req ipc.Request
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		_ = json.NewEncoder(writer).Encode(errorResponse("bad_request", "BAD_REQUEST", err.Error(), "Check JSON syntax and required fields."))
		return
	}
	resp := s.handle(req)
	_ = json.NewEncoder(writer).Encode(resp)
}

func errorResponse(errName, errCode, message, hint string) ipc.Response {
	return ipc.Response{
		OK:        false,
		Error:     errName,
		ErrorCode: errCode,
		Message:   message,
		Hint:      hint,
	}
}

func (s *Server) configSnapshot() *ipc.ConfigSnapshot {
	return &ipc.ConfigSnapshot{
		CaptureDir:         s.cfg.CaptureDir,
		CMDPath:            s.cfg.CMDPath,
		PipeName:           ipc.PipeName,
		IdleTimeoutSeconds: s.cfg.IdleTimeoutSeconds,
		MaxFileSizeBytes:   s.cfg.MaxFileSizeBytes,
		MaxHistoryTasks:    s.cfg.MaxHistoryTasks,
		MaxCaptureFiles:    s.cfg.MaxCaptureFiles,
		HistoryTaskTTLMinutes: s.cfg.HistoryTaskTTLMinutes,
	}
}

func sanitizeRequest(req *ipc.Request, cfg Config) {
	if req.DurationSeconds == 0 {
		req.DurationSeconds = defaultCaptureDurationSeconds
	}
	if req.IdleTimeoutSeconds == 0 {
		req.IdleTimeoutSeconds = cfg.IdleTimeoutSeconds
	}
	if req.MaxFileSizeBytes == 0 {
		req.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}
}

func validateCaptureRequest(req ipc.Request) *ipc.Response {
	if strings.TrimSpace(req.Interface) == "" && !req.AutoInterface {
		resp := errorResponse("invalid_request", "CAPTURE_TARGET_REQUIRED", "capture requires interface or autoInterface=true", "Pass an explicit interface or set autoInterface=true with vendorId/productId filters.")
		return &resp
	}
	if req.AutoInterface && strings.TrimSpace(req.VendorID) == "" && strings.TrimSpace(req.ProductID) == "" {
		resp := errorResponse("invalid_request", "AUTO_INTERFACE_FILTER_REQUIRED", "autoInterface requires vendorId or productId", "Provide vendorId, optionally with productId.")
		return &resp
	}
	if req.StoreMode != "" && req.StoreMode != "immediate" && req.StoreMode != "on-match" {
		resp := errorResponse("invalid_request", "INVALID_STORE_MODE", "storeMode must be 'immediate' or 'on-match'", "Use storeMode='on-match' for trigger-based storage.")
		return &resp
	}
	if req.DurationSeconds > 24*60*60 {
		resp := errorResponse("invalid_request", "DURATION_TOO_LARGE", "durationSeconds must be <= 86400", "Use at most 24 hours per capture request.")
		return &resp
	}
	if req.IdleTimeoutSeconds > 24*60*60 {
		resp := errorResponse("invalid_request", "IDLE_TIMEOUT_TOO_LARGE", "idleTimeoutSeconds must be <= 86400", "Use at most 24 hours for idle timeout.")
		return &resp
	}
	if req.MaxFileSizeBytes < 0 {
		resp := errorResponse("invalid_request", "INVALID_MAX_FILE_SIZE", "maxFileSizeBytes must be >= 0", "Use 0 to inherit service config or a positive byte limit.")
		return &resp
	}
	if strings.TrimSpace(req.Endpoint) != "" && !req.AppFilter {
		resp := errorResponse("invalid_request", "APP_FILTER_REQUIRED", "endpoint filtering requires appFilter=true", "Set appFilter=true when using endpoint or transferType.")
		return &resp
	}
	if strings.TrimSpace(req.TransferType) != "" && !req.AppFilter {
		resp := errorResponse("invalid_request", "APP_FILTER_REQUIRED", "transferType filtering requires appFilter=true", "Set appFilter=true when using endpoint or transferType.")
		return &resp
	}
	return nil
}

func (s *Server) nextID() string {
	return "capture-" + strconv.FormatUint(atomic.AddUint64(&s.nextTaskID, 1), 10)
}

func (s *Server) currentCaptureStatus() *ipc.CaptureStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil
	}
	return &ipc.CaptureStatus{
		Running:     true,
		Interface:   s.active.interfaceName,
		OutputPath:  s.active.outputPath,
		StartedAt:   s.active.startedAt,
		StoreMode:   s.active.storeMode,
		AutoStopSec: s.active.durationSec,
	}
}

func (s *Server) newTask(req ipc.Request, outputPath string) *captureTaskState {
	return &captureTaskState{
		task: ipc.CaptureTask{
			TaskID:     s.nextID(),
			Status:     "pending",
			Interface:  req.Interface,
			OutputPath: outputPath,
		},
		req:  req,
		done: make(chan struct{}),
	}
}

func (s *Server) registerTask(task *captureTaskState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks[task.task.TaskID] = task
}

func (s *Server) beginCapture(task *captureTaskState) (context.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil {
		return nil, fmt.Errorf("capture already in progress")
	}
	storeMode := task.req.StoreMode
	if storeMode == "" {
		storeMode = "immediate"
	}
	ctx, cancel := context.WithCancel(context.Background())
	task.cancel = cancel
	task.task.Status = "running"
	task.task.StoreMode = storeMode
	task.task.DurationSeconds = task.req.DurationSeconds
	task.task.StartedAt = time.Now()
	s.active = &activeCapture{
		taskID:        task.task.TaskID,
		interfaceName: task.req.Interface,
		outputPath:    task.task.OutputPath,
		storeMode:     storeMode,
		durationSec:   task.req.DurationSeconds,
		startedAt:     task.task.StartedAt,
		cancel:        cancel,
	}
	return ctx, nil
}

func (s *Server) recordHistory(task ipc.CaptureTask) {
	s.history = append([]ipc.CaptureTask{task}, s.history...)
	if len(s.history) > s.cfg.MaxHistoryTasks {
		s.history = s.history[:s.cfg.MaxHistoryTasks]
	}
	keep := make(map[string]struct{}, len(s.history))
	for _, item := range s.history {
		keep[item.TaskID] = struct{}{}
	}
	for id, item := range s.tasks {
		if item.task.Status == "running" {
			continue
		}
		if _, ok := keep[id]; !ok {
			delete(s.tasks, id)
		}
	}
	// Apply time-based cleanup
	s.cleanupHistory()
}

// cleanupHistory removes completed history tasks older than the configured TTL.
// Must be called with s.mu held.
func (s *Server) cleanupHistory() {
	ttlMinutes := s.cfg.HistoryTaskTTLMinutes
	if ttlMinutes <= 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(ttlMinutes) * time.Minute)

	var kept []ipc.CaptureTask
	for _, t := range s.history {
		if t.FinishedAt.IsZero() || t.FinishedAt.After(cutoff) {
			kept = append(kept, t)
		}
		// Remove from tasks map if older than TTL and not running
		if !t.FinishedAt.IsZero() && t.FinishedAt.Before(cutoff) {
			delete(s.tasks, t.TaskID)
		}
	}
	s.history = kept
}

// cleanupHistoryLocked is the public wrapper for periodic cleanup.
func (s *Server) cleanupHistoryLocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupHistory()
}

// startHistoryCleanup launches a periodic goroutine to clean old history tasks.
func (s *Server) startHistoryCleanup(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupHistoryLocked()
		}
	}
}

func (s *Server) endCapture(task *captureTaskState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil && s.active.taskID == task.task.TaskID {
		s.active = nil
	}
	task.task.FinishedAt = time.Now()
	s.recordHistory(task.task)
}

func (s *Server) stopCapture(code, message, hint string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return false
	}
	if task := s.tasks[s.active.taskID]; task != nil {
		task.stopCode = code
		task.stopMsg = message
		task.stopHint = hint
	}
	s.active.cancel()
	return true
}

// stopCaptureByTaskID stops a capture by taskId. Only works if the task is currently running.
func (s *Server) stopCaptureByTaskID(taskID, code, message, hint string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active == nil {
		return false, nil
	}
	if s.active.taskID != taskID {
		return false, fmt.Errorf("task %s is not the active capture", taskID)
	}
	if task := s.tasks[s.active.taskID]; task != nil {
		task.stopCode = code
		task.stopMsg = message
		task.stopHint = hint
	}
	s.active.cancel()
	return true, nil
}

func (s *Server) monitorCapture(ctx context.Context, task *captureTaskState) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(task.task.OutputPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				continue
			}
			if task.req.MaxFileSizeBytes > 0 && info.Size() >= task.req.MaxFileSizeBytes {
				s.stopCapture("CAPTURE_MAX_FILE_SIZE", "capture stopped after reaching maxFileSizeBytes", "Increase maxFileSizeBytes or shorten durationSeconds.")
				return
			}
			if task.req.IdleTimeoutSeconds > 0 && time.Since(info.ModTime()) > time.Duration(task.req.IdleTimeoutSeconds)*time.Second {
				s.stopCapture("CAPTURE_IDLE_TIMEOUT", "capture stopped after idle timeout", "Relax filters or increase idleTimeoutSeconds.")
				return
			}
		}
	}
}

func (s *Server) cleanupCaptureFiles() {
	entries, err := os.ReadDir(s.cfg.CaptureDir)
	if err != nil {
		return
	}
	type fileInfo struct {
		path string
		mod  time.Time
	}
	files := make([]fileInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".pcap") {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		files = append(files, fileInfo{path: filepath.Join(s.cfg.CaptureDir, entry.Name()), mod: info.ModTime()})
	}
	if len(files) <= s.cfg.MaxCaptureFiles {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for i := 0; i < len(files)-s.cfg.MaxCaptureFiles; i++ {
		_ = os.Remove(files[i].path)
	}
}

func (s *Server) finalizeTask(task *captureTaskState, path string, captureResp *usbpcapcmd.CaptureResult, err error) {
	defer close(task.done)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			if task.stopCode == "" {
				task.stopCode = "CAPTURE_STOPPED"
				task.stopMsg = "capture was stopped"
			}
			task.task.Status = "stopped"
			task.task.ErrorCode = task.stopCode
			task.task.Message = task.stopMsg
		} else {
			// Check for structured CmdError from USBPcapCMD (e.g. NO_MATCHED_DEVICE)
			var cmdErr *usbpcapcmd.CmdError
			if errors.As(err, &cmdErr) {
				task.task.ErrorCode = cmdErr.ErrorCode
				task.task.Message = cmdErr.Message
				task.task.Hint = cmdErr.Hint
				switch cmdErr.ErrorCode {
				case "NO_MATCHED_DEVICE":
					task.task.Status = "no_device"
					task.task.Hint = "Connect the device or verify VID/PID and retry."
				default:
					task.task.Status = "failed"
				}
			} else {
				task.task.Status = "failed"
				task.task.ErrorCode = "CAPTURE_FAILED"
				task.task.Message = err.Error()
			}
		}
		s.endCapture(task)
		s.cleanupCaptureFiles()
		return
	}

	task.task.Triggered = captureResp.Triggered
	task.task.MatchedDevices = captureResp.MatchedDevices
	task.task.StoreMode = captureResp.StoreMode
	if captureResp.Output == nil && !captureResp.Triggered {
		task.task.Status = "no-match"
		task.task.Message = strings.TrimSpace(captureResp.Reason)
		s.endCapture(task)
		s.cleanupCaptureFiles()
		return
	}
	summary, summaryErr := pcap.Summarize(path)
	if summaryErr != nil {
		task.task.Status = "failed"
		task.task.ErrorCode = "SUMMARY_FAILED"
		task.task.Message = summaryErr.Error()
		s.endCapture(task)
		s.cleanupCaptureFiles()
		return
	}
	summary.DroppedPackets = captureResp.DroppedPackets
	task.task.Summary = summary
	task.task.Status = "completed"

	// Check for idle device (matched but no traffic)
	if summary.PacketCount == 0 {
		if len(task.task.MatchedDevices) > 0 {
			task.task.Status = "idle"
			task.task.Message = "Device(s) found but no traffic captured. Device may be idle."
			task.task.Hint = "Trigger device activity (e.g. GUI capture) or restart the device."
		} else {
			task.task.Status = "idle"
			task.task.Message = "Capture completed with 0 packets. No matching device traffic seen."
			task.task.Hint = "Check device connection or use a different interface."
		}
	}
	s.endCapture(task)
	s.cleanupCaptureFiles()
}

func (s *Server) runStartedTask(ctx context.Context, task *captureTaskState) {
	go s.monitorCapture(ctx, task)
	resp, runErr := s.runner.CaptureContext(ctx, task.req, task.task.OutputPath)
	s.finalizeTask(task, task.task.OutputPath, resp, runErr)
}

func (s *Server) dropTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tasks, taskID)
}

func (s *Server) taskByID(taskID string) *ipc.CaptureTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	if task := s.tasks[taskID]; task != nil {
		copy := task.task
		return &copy
	}
	return nil
}

func (s *Server) listTasks() []ipc.CaptureTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ipc.CaptureTask, 0, len(s.history)+1)
	if s.active != nil {
		if task := s.tasks[s.active.taskID]; task != nil {
			out = append(out, task.task)
		}
	}
	out = append(out, s.history...)
	return out
}

func (s *Server) defaultOutputPath(name string) string {
	if name == "" {
		now := time.Now()
		name = fmt.Sprintf("usbpcap-%s-%03d.pcap", now.Format("20060102-150405"), now.Nanosecond()/1_000_000)
	}
	return filepath.Join(s.cfg.CaptureDir, filepath.Base(name))
}

// normalizeHex normalizes a hex string like "1a86" or "0X1A86" to "0x1a86".
// Returns the original string if it can't be parsed as valid hex.
func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	raw := strings.TrimPrefix(s, "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if _, err := strconv.ParseUint(raw, 16, 16); err != nil {
		return s
	}
	return "0x" + strings.ToLower(raw)
}

// normalizeInterface ensures interface uses the full \\.\USBPcapN format.
func normalizeInterface(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.HasPrefix(s, `\\.\`) {
		return s
	}
	if strings.HasPrefix(s, "USBPcap") || strings.HasPrefix(s, "usbpcap") {
		return `\\.\` + s
	}
	return s
}

// normalizeRequest normalizes common AI input errors in the request in-place.
// Returns a map of normalized fields for inclusion in the response.
func normalizeRequest(req *ipc.Request) map[string]any {
	normalized := make(map[string]any)

	if req.VendorID != "" {
		n := normalizeHex(req.VendorID)
		if n != req.VendorID {
			normalized["vendorId"] = n
			req.VendorID = n
		}
	}
	if req.ProductID != "" {
		n := normalizeHex(req.ProductID)
		if n != req.ProductID {
			normalized["productId"] = n
			req.ProductID = n
		}
	}
	if req.Endpoint != "" {
		n := normalizeHex(req.Endpoint)
		if n != req.Endpoint {
			normalized["endpoint"] = n
			req.Endpoint = n
		}
	}
	if req.Interface != "" {
		n := normalizeInterface(req.Interface)
		if n != req.Interface {
			normalized["interface"] = n
			req.Interface = n
		}
	}
	// Auto-enable appFilter if endpoint/transferType is set but appFilter is not
	if (req.Endpoint != "" || req.TransferType != "") && !req.AppFilter {
		req.AppFilter = true
		normalized["appFilter"] = true
	}
	return normalized
}

// probeDevices scans all USBPcap interfaces for devices matching the given VID/PID.
func (s *Server) probeDevices(vendorId, productId string) ([]ipc.MatchedDevice, error) {
	ifs, err := s.runner.ListInterfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var allMatches []ipc.MatchedDevice
	for _, iface := range ifs {
		devs, err := s.runner.ListDevices(iface.Name)
		if err != nil {
			continue
		}
		for _, dev := range devs {
			vendorMatch := vendorId == "" || strings.EqualFold(dev.VendorID, vendorId)
			productMatch := productId == "" || strings.EqualFold(dev.ProductID, productId)
			if vendorMatch && productMatch {
				allMatches = append(allMatches, ipc.MatchedDevice{
					Interface: iface.Name,
					Address:   dev.Address,
					VendorID:  dev.VendorID,
					ProductID: dev.ProductID,
				})
			}
		}
	}
	return allMatches, nil
}

// nextActionForTool creates a NextAction pointer for a given tool and arguments.
func nextActionForTool(tool string, args map[string]any) *ipc.NextAction {
	return &ipc.NextAction{Tool: tool, Arguments: args}
}

// computeNextAction returns the recommended next tool based on task status.
func (s *Server) computeNextAction(task *ipc.CaptureTask) *ipc.NextAction {
	switch task.Status {
	case "completed":
		return nextActionForTool("usbpcap_analyze", map[string]any{
			"pcapPath": task.OutputPath,
		})
	case "idle":
		return nextActionForTool("usbpcap_capture_status", map[string]any{})
	case "no_device", "no-match":
		return nextActionForTool("usbpcap_probe_device", map[string]any{})
	default:
		return nil
	}
}

func (s *Server) handle(req ipc.Request) ipc.Response {
	sanitizeRequest(&req, s.cfg)
	normalized := normalizeRequest(&req)

	switch req.Action {
	case "listInterfaces":
		ifs, err := s.runner.ListInterfaces()
		if err != nil {
			return errorResponse("list_interfaces_failed", "LIST_INTERFACES_FAILED", err.Error(), "Verify USBPcapCap.exe path and that USBPcap is installed.")
		}
		return ipc.Response{OK: true, Status: "ok", Interfaces: ifs, StartedAt: s.startedAt, NormalizedArguments: normalized}
	case "listDevices":
		if strings.TrimSpace(req.Interface) == "" {
			return errorResponse("invalid_request", "INTERFACE_REQUIRED", "interface is required for listDevices", "Pass the interface returned by usbpcap_list_interfaces.")
		}
		devs, err := s.runner.ListDevices(req.Interface)
		if err != nil {
			return errorResponse("list_devices_failed", "LIST_DEVICES_FAILED", err.Error(), "Verify the selected interface exists and is not malformed.")
		}
		return ipc.Response{OK: true, Status: "ok", Devices: devs, StartedAt: s.startedAt, NormalizedArguments: normalized}
	case "probeDevice":
		return s.handleProbeDevice(req, normalized)
	case "captureOnce":
		if resp := validateCaptureRequest(req); resp != nil {
			resp.NormalizedArguments = normalized
			return *resp
		}
		task := s.newTask(req, s.defaultOutputPath(req.OutputFileName))
		s.registerTask(task)
		ctx, err := s.beginCapture(task)
		if err != nil {
			s.dropTask(task.task.TaskID)
			resp := errorResponse("capture_busy", "CAPTURE_BUSY", err.Error(), "Wait for the current capture to finish or call usbpcap_stop_capture first.")
			resp.NormalizedArguments = normalized
			return resp
		}
		go s.runStartedTask(ctx, task)
		<-task.done
		resp := ipc.Response{
			OK:                 true,
			Status:             task.task.Status,
			PCAPPath:           task.task.OutputPath,
			Triggered:          task.task.Triggered,
			StoreMode:          task.task.StoreMode,
			MatchedDevices:     task.task.MatchedDevices,
			Summary:            task.task.Summary,
			Task:               &task.task,
			StartedAt:          s.startedAt,
			NormalizedArguments: normalized,
		}
		resp.NextAction = s.computeNextAction(&task.task)
		return resp
	case "startCapture":
		if resp := validateCaptureRequest(req); resp != nil {
			resp.NormalizedArguments = normalized
			return *resp
		}
		task := s.newTask(req, s.defaultOutputPath(req.OutputFileName))
		s.registerTask(task)
		ctx, err := s.beginCapture(task)
		if err != nil {
			s.dropTask(task.task.TaskID)
			resp := errorResponse("capture_busy", "CAPTURE_BUSY", err.Error(), "Wait for the current capture to finish or call usbpcap_stop_capture first.")
			resp.NormalizedArguments = normalized
			return resp
		}
		go s.runStartedTask(ctx, task)
		return ipc.Response{
			OK: true, Status: "task_started",
			Message:             "capture task started",
			Task:                &task.task,
			StartedAt:           s.startedAt,
			NormalizedArguments: normalized,
			NextAction:          nextActionForTool("usbpcap_wait_capture_task", map[string]any{"taskId": task.task.TaskID}),
		}
	case "waitCaptureTask":
		return s.handleWaitCaptureTask(req, normalized)
	case "smartCapture":
		return s.handleSmartCapture(req, normalized)
	case "analyze":
		return s.handleAnalyze(req, normalized)
	case "diagnoseCapture":
		return s.handleDiagnoseCapture(req, normalized)
	case "profileDevice":
		return s.handleProfileDevice(req, normalized)
	case "exportData":
		return s.handleExportData(req, normalized)
	case "getCaptureTask":
		if strings.TrimSpace(req.TaskID) == "" {
			return errorResponse("invalid_request", "TASK_ID_REQUIRED", "taskId is required", "Pass the taskId returned by startCapture.")
		}
		task := s.taskByID(req.TaskID)
		if task == nil {
			return errorResponse("task_not_found", "TASK_NOT_FOUND", "capture task not found", "Use listCaptureTasks to inspect recent history.")
		}
		resp := ipc.Response{OK: true, Status: task.Status, Task: task, StartedAt: s.startedAt, NormalizedArguments: normalized}
		resp.NextAction = s.computeNextAction(task)
		return resp
	case "listCaptureTasks":
		return ipc.Response{OK: true, Status: "ok", Tasks: s.listTasks(), StartedAt: s.startedAt, NormalizedArguments: normalized}
	case "status":
		return ipc.Response{OK: true, Status: "ok", Message: "service is running", ActiveCapture: s.currentCaptureStatus(), Tasks: s.listTasks(), Config: s.configSnapshot(), StartedAt: s.startedAt, NormalizedArguments: normalized}
	case "stopCapture":
		if strings.TrimSpace(req.TaskID) != "" {
			stopped, stopErr := s.stopCaptureByTaskID(req.TaskID, "CAPTURE_STOPPED", "capture was stopped", "Retry the capture when ready.")
			if stopErr != nil {
				return errorResponse("stop_failed", "STOP_FAILED", stopErr.Error(),
					"Specify the currently active task or omit taskId for default stop.")
			}
			if !stopped {
				return errorResponse("capture_not_running", "CAPTURE_NOT_RUNNING",
					"no capture is currently running with the given taskId",
					"Check active capture with usbpcap_capture_status.")
			}
			return ipc.Response{OK: true, Status: "stopped", Message: "capture stop requested", StartedAt: s.startedAt, NormalizedArguments: normalized}
		}
		if !s.stopCapture("CAPTURE_STOPPED", "capture was stopped", "Retry the capture when ready.") {
			return errorResponse("capture_not_running", "CAPTURE_NOT_RUNNING", "no capture is currently running", "Start a capture before calling stop.")
		}
		return ipc.Response{OK: true, Status: "stopped", Message: "capture stop requested", ActiveCapture: s.currentCaptureStatus(), StartedAt: s.startedAt, NormalizedArguments: normalized}
	case "getConfig":
		return ipc.Response{OK: true, Status: "ok", Config: s.configSnapshot(), StartedAt: s.startedAt, NormalizedArguments: normalized}
	case "help":
		return ipc.Response{OK: true, Status: "ok", Help: defaultHelp(), StartedAt: s.startedAt, NormalizedArguments: normalized}
	default:
		return errorResponse("unknown_action", "UNKNOWN_ACTION", req.Action, "Use the MCP tools list or call help.")
	}
}

// handleProbeDevice scans all USBPcap interfaces and returns matching devices.
func (s *Server) handleProbeDevice(req ipc.Request, normalized map[string]any) ipc.Response {
	if strings.TrimSpace(req.VendorID) == "" && strings.TrimSpace(req.ProductID) == "" {
		return ipc.Response{
			OK: false, Status: "no_filter",
			Error: "invalid_request", ErrorCode: "PROBE_FILTER_REQUIRED",
			Message:              "probe requires vendorId or productId",
			Hint:                 "Provide vendorId, optionally with productId.",
			NormalizedArguments:   normalized,
		}
	}
	matches, err := s.probeDevices(req.VendorID, req.ProductID)
	if err != nil {
		return errorResponse("probe_failed", "PROBE_FAILED", err.Error(),
			"Verify USBPcapCap.exe path and that USBPcap is installed.")
	}
	if len(matches) == 0 {
		return ipc.Response{
			OK: false, Status: "no_device",
			Error: "no_match", ErrorCode: "NO_MATCHED_DEVICE",
			Message:            "No connected USB device matched the requested VID/PID.",
			Hint:               "Check device connection or run usbpcap_list_interfaces first.",
			MatchedDevices:     matches,
			NormalizedArguments: normalized,
			NextAction:         nextActionForTool("usbpcap_list_interfaces", nil),
		}
	}
	if len(matches) > 1 {
		return ipc.Response{
			OK: false, Status: "ambiguous_device",
			Error: "multiple_matches", ErrorCode: "AMBIGUOUS_DEVICE",
			Message:            fmt.Sprintf("Found %d matching devices across multiple interfaces.", len(matches)),
			Hint:               "Specify an explicit interface to disambiguate.",
			MatchedDevices:     matches,
			NormalizedArguments: normalized,
		}
	}
	return ipc.Response{
		OK: true, Status: "found",
		Message:            "Found unique matching device.",
		MatchedDevices:     matches,
		NormalizedArguments: normalized,
		NextAction: nextActionForTool("usbpcap_smart_capture", map[string]any{
			"interface":  matches[0].Interface,
			"vendorId":   req.VendorID,
			"productId":  req.ProductID,
		}),
	}
}

// handleWaitCaptureTask blocks until the specified task completes or times out.
func (s *Server) handleWaitCaptureTask(req ipc.Request, normalized map[string]any) ipc.Response {
	if strings.TrimSpace(req.TaskID) == "" {
		return errorResponse("invalid_request", "TASK_ID_REQUIRED",
			"taskId is required", "Pass the taskId returned by startCapture.")
	}

	// Look up task state
	s.mu.Lock()
	taskState, exists := s.tasks[req.TaskID]
	s.mu.Unlock()

	if !exists {
		task := s.taskByID(req.TaskID)
		if task == nil {
			return errorResponse("task_not_found", "TASK_NOT_FOUND",
				"capture task not found", "Use listCaptureTasks to inspect recent history.")
		}
		resp := ipc.Response{OK: true, Status: task.Status, Task: task, StartedAt: s.startedAt, NormalizedArguments: normalized}
		resp.NextAction = s.computeNextAction(task)
		return resp
	}

	timeout := time.Duration(60) * time.Second
	if req.DurationSeconds > 0 {
		timeout = time.Duration(req.DurationSeconds) * time.Second
	}

	select {
	case <-taskState.done:
	case <-time.After(timeout):
		task := s.taskByID(req.TaskID)
		if task == nil {
			return ipc.Response{
				OK: false, Status: "timeout",
				Error: "timeout", ErrorCode: "WAIT_TIMEOUT",
				Message:            "wait timed out but task may still be running",
				Hint:               "Call getCaptureTask to check status.",
				NormalizedArguments: normalized,
			}
		}
		resp := ipc.Response{OK: true, Status: "timeout", Task: task, StartedAt: s.startedAt, NormalizedArguments: normalized}
		if task.Status == "running" || task.Status == "pending" {
			resp.Message = "Task is still running. Retry wait or use getCaptureTask."
			resp.NextAction = nextActionForTool("usbpcap_wait_capture_task", map[string]any{
				"taskId": req.TaskID, "timeoutSeconds": 60,
			})
		}
		return resp
	}

	task := s.taskByID(req.TaskID)
	if task == nil {
		return errorResponse("internal_error", "TASK_LOST",
			"task completed but could not be retrieved", "")
	}
	resp := ipc.Response{OK: true, Status: task.Status, Task: task, StartedAt: s.startedAt, NormalizedArguments: normalized}
	if task.Status == "completed" {
		resp.PCAPPath = task.OutputPath
		resp.Summary = task.Summary
		resp.MatchedDevices = task.MatchedDevices
	}
	resp.NextAction = s.computeNextAction(task)
	return resp
}

// handleSmartCapture combines probe + capture + wait + analyze in one step.
func (s *Server) handleSmartCapture(req ipc.Request, normalized map[string]any) ipc.Response {
	// If no interface, try probe
	if strings.TrimSpace(req.Interface) == "" && !req.AutoInterface {
		if strings.TrimSpace(req.VendorID) == "" && strings.TrimSpace(req.ProductID) == "" {
			return ipc.Response{
				OK: false, Status: "target_required",
				Error: "invalid_request", ErrorCode: "CAPTURE_TARGET_REQUIRED",
				Message:             "smart_capture requires interface, vendorId, or productId",
				Hint:                "Pass an interface or vendorId/productId for auto-detection.",
				NormalizedArguments: normalized,
			}
		}
		matches, probeErr := s.probeDevices(req.VendorID, req.ProductID)
		if probeErr != nil {
			return errorResponse("probe_failed", "PROBE_FAILED", probeErr.Error(),
				"Verify USBPcapCap.exe path and USBPcap installation.")
		}
		if len(matches) == 0 {
			return ipc.Response{
				OK: false, Status: "no_device",
				Error: "no_match", ErrorCode: "NO_MATCHED_DEVICE",
				Message:            "No device found matching the requested VID/PID.",
				Hint:               "Check device connection and try again.",
				MatchedDevices:     matches,
				NormalizedArguments: normalized,
				NextAction: nextActionForTool("usbpcap_probe_device", map[string]any{
					"vendorId": req.VendorID, "productId": req.ProductID,
				}),
			}
		}
		if len(matches) > 1 {
			return ipc.Response{
				OK: false, Status: "ambiguous_device",
				Error: "multiple_matches", ErrorCode: "AMBIGUOUS_DEVICE",
				Message:            fmt.Sprintf("Found %d matching devices. Specify an interface.", len(matches)),
				Hint:               "Use one of the returned interfaces explicitly.",
				MatchedDevices:     matches,
				NormalizedArguments: normalized,
			}
		}
		req.Interface = matches[0].Interface
		if normalized == nil {
			normalized = make(map[string]any)
		}
		normalized["interface"] = req.Interface
	}
	req.AutoInterface = false

	if resp := validateCaptureRequest(req); resp != nil {
		resp.NormalizedArguments = normalized
		return *resp
	}

	task := s.newTask(req, s.defaultOutputPath(req.OutputFileName))
	s.registerTask(task)
	ctx, err := s.beginCapture(task)
	if err != nil {
		s.dropTask(task.task.TaskID)
		resp := errorResponse("capture_busy", "CAPTURE_BUSY", err.Error(),
			"Wait for the current capture to finish first.")
		resp.NormalizedArguments = normalized
		return resp
	}
	go s.runStartedTask(ctx, task)
	<-task.done

	resp := ipc.Response{
		OK:                 true,
		Status:             task.task.Status,
		Task:               &task.task,
		StartedAt:          s.startedAt,
		NormalizedArguments: normalized,
	}

	switch task.task.Status {
	case "completed":
		resp.PCAPPath = task.task.OutputPath
		resp.Summary = task.task.Summary
		resp.MatchedDevices = task.task.MatchedDevices
		resp.NextAction = nextActionForTool("usbpcap_analyze", map[string]any{
			"pcapPath": task.task.OutputPath,
		})
	case "idle":
		resp.Message = task.task.Message
		resp.Hint = task.task.Hint
		resp.NextAction = nextActionForTool("usbpcap_smart_capture", map[string]any{
			"vendorId":        req.VendorID,
			"productId":       req.ProductID,
			"durationSeconds": 30,
			"storeMode":       "on-match",
		})
	case "no-match", "no_device":
		resp.Message = task.task.Message
		resp.NextAction = nextActionForTool("usbpcap_diagnose_capture", map[string]any{
			"taskId": task.task.TaskID,
		})
	default:
		resp.Message = task.task.Message
		if task.task.ErrorCode != "" {
			resp.ErrorCode = task.task.ErrorCode
			resp.OK = false
		}
	}
	return resp
}

// handleAnalyze returns structured USB traffic analysis for a pcap file.
func (s *Server) handleAnalyze(req ipc.Request, normalized map[string]any) ipc.Response {
	if strings.TrimSpace(req.PCAPPath) == "" {
		// If taskId given, use its output path
		if strings.TrimSpace(req.TaskID) != "" {
			task := s.taskByID(req.TaskID)
			if task == nil {
				return errorResponse("task_not_found", "TASK_NOT_FOUND",
					"capture task not found", "Use listCaptureTasks to inspect recent history.")
			}
			req.PCAPPath = task.OutputPath
		}
	}
	pcapPath := req.PCAPPath
	if pcapPath == "" {
		return errorResponse("invalid_request", "PCAP_PATH_REQUIRED",
			"pcapPath is required", "Pass the pcap file path or a taskId from a completed capture.")
	}
	if !filepath.IsAbs(pcapPath) {
		pcapPath = filepath.Join(s.cfg.CaptureDir, filepath.Base(pcapPath))
	}
	result, err := pcap.Analyze(pcapPath, nil)
	if err != nil {
		return errorResponse("analyze_failed", "ANALYZE_FAILED", err.Error(),
			"Verify the pcap file exists and is a valid USBPcap capture.")
	}
	if req.DeviceAddress != nil && *req.DeviceAddress > 0 {
		addr := uint16(*req.DeviceAddress)
		result, err = pcap.Analyze(pcapPath, &addr)
		if err != nil {
			return errorResponse("analyze_failed", "ANALYZE_FAILED", err.Error(), "")
		}
	}
	return ipc.Response{
		OK: true, Status: "ok",
		Message:            fmt.Sprintf("Analyzed %d endpoints from %s", len(result.Endpoints), filepath.Base(pcapPath)),
		PCAPPath:           pcapPath,
		AnalyzeResult:      result,
		NormalizedArguments: normalized,
	}
}

// handleDiagnoseCapture diagnoses why a capture produced no or unexpected data.
func (s *Server) handleDiagnoseCapture(req ipc.Request, normalized map[string]any) ipc.Response {
	taskID := req.TaskID
	if taskID == "" {
		return errorResponse("invalid_request", "TASK_ID_REQUIRED",
			"taskId is required for diagnosis", "Pass a taskId from a failed or empty capture.")
	}

	task := s.taskByID(taskID)
	if task == nil {
		return ipc.Response{
			OK: false, Status: "task_not_found",
			Error: "task_not_found", ErrorCode: "TASK_NOT_FOUND",
			Message:            "capture task not found for diagnosis",
			Hint:               "Use listCaptureTasks to find recent tasks.",
			NormalizedArguments: normalized,
		}
	}

	d := s.diagnoseTask(task, req.VendorID, req.ProductID)
	return ipc.Response{
		OK: true, Status: "diagnosis",
		DiagnosisResult:  d,
		NormalizedArguments: normalized,
	}
}

// diagnoseTask builds a DiagnosisResult from a completed task.
func (s *Server) diagnoseTask(task *ipc.CaptureTask, vendorID, productID string) *ipc.DiagnosisResult {
	d := &ipc.DiagnosisResult{Confidence: 0.9}

	switch task.Status {
	case "no_device":
		d.Diagnosis = "NO_DEVICE"
		d.Recommendation = "No matching device found. Check device connection and verify VID/PID."
		d.NextAction = nextActionForTool("usbpcap_probe_device", map[string]any{
			"vendorId": vendorID, "productId": productID,
		})
		return d

	case "idle":
		d.Diagnosis = "DEVICE_IDLE"
		d.Confidence = 0.85
		d.Recommendation = "Device found but no USB traffic captured. Trigger device activity or extend capture duration."
		d.NextAction = nextActionForTool("usbpcap_smart_capture", map[string]any{
			"vendorId":        vendorID,
			"productId":       productID,
			"durationSeconds": 30,
			"storeMode":       "on-match",
		})
		return d

	case "no-match":
		d.Diagnosis = "FILTER_TOO_STRICT"
		d.Recommendation = "on-match mode found no matching packets. Try removing endpoint/transferType filters."
		d.NextAction = nextActionForTool("usbpcap_smart_capture", map[string]any{
			"vendorId":  vendorID,
			"productId": productID,
			"appFilter": false,
		})
		return d

	case "completed":
		if task.Summary != nil && task.Summary.PacketCount == 0 {
			d.Diagnosis = "PCAP_EMPTY"
			d.Confidence = 0.8
			d.Recommendation = "Capture completed but pcap has zero packets. Device may be idle."
			d.NextAction = nextActionForTool("usbpcap_smart_capture", map[string]any{
				"vendorId":  vendorID,
				"productId": productID,
				"durationSeconds": 30,
			})
			return d
		}
		// If there are packets, no diagnosis needed
		d.Diagnosis = "OK"
		d.Confidence = 1.0
		d.Recommendation = "Capture has data. Use analyze to inspect endpoints."
		d.NextAction = nextActionForTool("usbpcap_analyze", map[string]any{
			"pcapPath": task.OutputPath,
		})
		return d

	case "failed":
		switch task.ErrorCode {
		case "NO_MATCHED_DEVICE":
			d.Diagnosis = "NO_DEVICE"
		case "SUMMARY_FAILED":
			d.Diagnosis = "PCAP_UNSUPPORTED"
		default:
			d.Diagnosis = "NO_PERMISSION"
			d.Confidence = 0.6
		}
		d.Recommendation = fmt.Sprintf("Task failed with %s: %s", task.ErrorCode, task.Message)
		d.NextAction = nextActionForTool("usbpcap_help", nil)
		return d

	case "stopped":
		d.Diagnosis = "CAPTURE_STOPPED"
		d.Recommendation = "Capture was stopped by user or by limit (size/time)."
		// If we have a pcap with data, still suggest analyze
		if task.OutputPath != "" && task.Summary != nil && task.Summary.PacketCount > 0 {
			d.NextAction = nextActionForTool("usbpcap_analyze", map[string]any{
				"pcapPath": task.OutputPath,
			})
		}
		return d

	default:
		d.Diagnosis = "UNKNOWN"
		d.Confidence = 0.5
		d.Recommendation = fmt.Sprintf("Task status: %s. Consult usbpcap_help for guidance.", task.Status)
		return d
	}
}

// handleProfileDevice probes a device, does a short capture, and returns endpoint profile.
func (s *Server) handleProfileDevice(req ipc.Request, normalized map[string]any) ipc.Response {
	if strings.TrimSpace(req.VendorID) == "" && strings.TrimSpace(req.ProductID) == "" {
		return ipc.Response{
			OK: false, Status: "filter_required",
			Error: "invalid_request", ErrorCode: "PROFILE_FILTER_REQUIRED",
			Message:             "profile_device requires vendorId or productId",
			Hint:                "Provide vendorId to identify the device to profile.",
			NormalizedArguments: normalized,
		}
	}

	// Probe first
	matches, err := s.probeDevices(req.VendorID, req.ProductID)
	if err != nil {
		return errorResponse("probe_failed", "PROBE_FAILED", err.Error(),
			"Verify USBPcapCap.exe path and USBPcap installation.")
	}
	if len(matches) == 0 {
		return ipc.Response{
			OK: false, Status: "no_device",
			Error: "no_match", ErrorCode: "NO_MATCHED_DEVICE",
			Message:            "No device found for profiling.",
			Hint:               "Check device connection and try again.",
			NormalizedArguments: normalized,
		}
	}
	if len(matches) > 1 {
		return ipc.Response{
			OK: false, Status: "ambiguous_device",
			Error: "multiple_matches", ErrorCode: "AMBIGUOUS_DEVICE",
			Message:            fmt.Sprintf("Found %d matching devices. Specify an interface.", len(matches)),
			MatchedDevices:     matches,
			NormalizedArguments: normalized,
		}
	}

	match := matches[0]
	duration := req.DurationSeconds
	if duration == 0 {
		duration = 10
	}

	// Do a short capture
	captureReq := ipc.Request{
		Interface:       match.Interface,
		VendorID:        req.VendorID,
		ProductID:       req.ProductID,
		DurationSeconds: duration,
		StoreMode:       "immediate",
	}
	outputPath := s.defaultOutputPath("profile-" + filepath.Base(match.Interface) + ".pcap")
	task := s.newTask(captureReq, outputPath)
	s.registerTask(task)
	ctx, ctxErr := s.beginCapture(task)
	if ctxErr != nil {
		s.dropTask(task.task.TaskID)
		return errorResponse("capture_busy", "CAPTURE_BUSY", ctxErr.Error(),
			"Wait for current capture to finish.")
	}
	go s.runStartedTask(ctx, task)
	<-task.done

	if task.task.Status != "completed" || task.task.Summary == nil || task.task.Summary.PacketCount == 0 {
		diagnosis := s.diagnoseTask(&task.task, req.VendorID, req.ProductID)
		return ipc.Response{
			OK: false, Status: task.task.Status,
			Error: "profile_no_data", ErrorCode: "PROFILE_NO_DATA",
			Message:           fmt.Sprintf("Profile capture produced no data (%s).", task.task.Status),
			DiagnosisResult:   diagnosis,
			NormalizedArguments: normalized,
		}
	}

	// Analyze the capture
	result, err := pcap.Analyze(outputPath, &match.Address)
	if err != nil {
		return errorResponse("analyze_failed", "ANALYZE_FAILED", err.Error(), "")
	}

	profile := &ipc.ProfileResult{
		Device:          match,
		DurationSeconds: duration,
		PacketCount:     task.task.Summary.PacketCount,
		Endpoints:       result.Endpoints,
	}

	// Build recommended capture params
	if len(result.Endpoints) > 0 {
		// Pick the highest-traffic IN endpoint
		var bestEP *ipc.EndpointStat
		for _, ep := range result.Endpoints {
			if ep.Direction == "IN" && (bestEP == nil || ep.PacketCount > bestEP.PacketCount) {
				bestEP = &ep
			}
		}
		if bestEP != nil {
			profile.Recommended = map[string]any{
				"interface":    match.Interface,
				"vendorId":     match.VendorID,
				"productId":    match.ProductID,
				"endpoint":     bestEP.Endpoint,
				"appFilter":    true,
				"transferType": bestEP.TransferType,
			}
		}
	}

	return ipc.Response{
		OK: true, Status: "ok",
		ProfileResult:    profile,
		PCAPPath:         outputPath,
		NormalizedArguments: normalized,
		NextAction: nextActionForTool("usbpcap_smart_capture", map[string]any{
			"interface":  match.Interface,
			"vendorId":   match.VendorID,
			"productId":  match.ProductID,
		}),
	}
}

// safePcapPath ensures the path is within the configured capture directory.
func (s *Server) safePcapPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("pcap path is empty")
	}
	// Allow paths within the capture dir
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(s.cfg.CaptureDir, abs)
	}
	abs = filepath.Clean(abs)
	captureDir := filepath.Clean(s.cfg.CaptureDir)
	if !strings.HasPrefix(abs, captureDir) {
		return "", errors.New("pcap path must be within the capture directory")
	}
	if !strings.EqualFold(filepath.Ext(abs), ".pcap") {
		return "", errors.New("file must have .pcap extension")
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("pcap file not accessible: %w", err)
	}
	return abs, nil
}

// handleExportData exports payload from a pcap file.
func (s *Server) handleExportData(req ipc.Request, normalized map[string]any) ipc.Response {
	ep := req.Endpoint
	if ep == "" {
		return errorResponse("invalid_request", "ENDPOINT_REQUIRED",
			"endpoint is required for export", "Specify the target endpoint (e.g. 0x81).")
	}

	pcapPath, err := s.safePcapPath(req.PCAPPath)
	if err != nil {
		return errorResponse("invalid_path", "INVALID_PCAP_PATH", err.Error(),
			"Specify a valid .pcap path within the capture directory.")
	}

	devAddr := uint16(0)
	if req.DeviceAddress != nil {
		devAddr = uint16(*req.DeviceAddress)
	}

	payloads, err := pcap.ExportPayload(pcapPath, devAddr, ep, req.MinDataLen)
	if err != nil {
		return errorResponse("export_failed", "EXPORT_FAILED", err.Error(),
			"Verify the pcap file is valid and contains packets for the specified device+endpoint.")
	}

	var exportContent string
	format := req.Format
	if format == "" {
		format = "hex"
	}

	switch format {
	case "hex":
		exportContent = strings.Join(payloads, "\n")
	case "csv":
		var b strings.Builder
		b.WriteString("index,payload_hex,payload_length\n")
		for i, p := range payloads {
			b.WriteString(fmt.Sprintf("%d,%s,%d\n", i, p, len(p)/2))
		}
		exportContent = b.String()
	case "raw":
		exportContent = strings.Join(payloads, "")
	default:
		exportContent = strings.Join(payloads, "\n")
	}

	resp := ipc.Response{
		OK: true, Status: "ok",
		Message:            fmt.Sprintf("Exported %d payload(s) from %s", len(payloads), filepath.Base(pcapPath)),
		PCAPPath:           pcapPath,
		ExportContent:      exportContent,
		NormalizedArguments: normalized,
	}

	// Optionally write to a file in captureDir/exports
	outputName := req.OutputFileName
	if outputName != "" {
		outputName = filepath.Base(outputName)
		exportDir := filepath.Join(s.cfg.CaptureDir, "exports")
		if err := os.MkdirAll(exportDir, 0o755); err == nil {
			outPath := filepath.Join(exportDir, outputName)
			_ = os.WriteFile(outPath, []byte(exportContent), 0o644)
			resp.ExportPath = outPath
		}
	}

	return resp
}

func defaultHelp() string {
	return strings.TrimSpace(`Actions:
- listInterfaces
- listDevices { interface }
- probeDevice { vendorId, productId }
- smartCapture { interface|vendorId, productId, durationSeconds, endpoint, transferType, storeMode }
- captureOnce { interface|autoInterface, vendorId, productId, durationSeconds, endpoint, transferType, storeMode, idleTimeoutSeconds, maxFileSizeBytes }
- startCapture { interface|autoInterface, vendorId, productId, durationSeconds, endpoint, transferType, storeMode, idleTimeoutSeconds, maxFileSizeBytes }
- waitCaptureTask { taskId, timeoutSeconds }
- analyze { pcapPath, taskId, deviceAddress }
- diagnoseCapture { taskId, vendorId, productId }
- profileDevice { vendorId, productId, durationSeconds }
- exportData { pcapPath, deviceAddress, endpoint, format, minDataLen, outputFileName }
- getCaptureTask { taskId }
- listCaptureTasks
- stopCapture
- getConfig
- status
- help

Notes:
- captureNewDevices captures any newly attached device, not only matching VID/PID.
- storeMode=on-match delays file creation until a matching packet is seen.
- endpoint filtering is application-layer filtering.

AI-friendly tools:
- smartCapture: auto probe + capture + analyze in one step.
- probeDevice: auto-discover which interface a device is on.
- waitCaptureTask: block until an async capture finishes.
- analyze: detailed endpoint and payload analysis.
- diagnoseCapture: diagnose empty/failed captures with structured output.
- profileDevice: short sample to discover endpoints and recommend params.
- exportData: extract payload hex/CSV/raw from pcap.
- All responses include status/nextAction for AI-guided execution.

Discovery:
- Use listInterfaces first.
- Use probeDevice when you only know VID/PID.
- Then use smartCapture with the resolved interface.

Capture:
- Prefer interface for deterministic capture.
- Use autoInterface only with vendorId/productId filters.
- durationSeconds must be between 0 and 86400 and defaults to 10 when omitted.
- idleTimeoutSeconds and maxFileSizeBytes default to service config when omitted.
- Only one capture runs at a time; use stopCapture to cancel the current capture.

History:
- startCapture returns taskId immediately.
- Use waitCaptureTask or getCaptureTask to inspect tasks.
- smartCapture blocks until completion.`)
}
