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
			task.task.Status = "failed"
			task.task.ErrorCode = "CAPTURE_FAILED"
			task.task.Message = err.Error()
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

func (s *Server) handle(req ipc.Request) ipc.Response {
	sanitizeRequest(&req, s.cfg)
	switch req.Action {
	case "listInterfaces":
		ifs, err := s.runner.ListInterfaces()
		if err != nil {
			return errorResponse("list_interfaces_failed", "LIST_INTERFACES_FAILED", err.Error(), "Verify USBPcapCMD.exe path and that USBPcap is installed.")
		}
		return ipc.Response{OK: true, Interfaces: ifs, StartedAt: s.startedAt}
	case "listDevices":
		if strings.TrimSpace(req.Interface) == "" {
			return errorResponse("invalid_request", "INTERFACE_REQUIRED", "interface is required for listDevices", "Pass the interface returned by usbpcap_list_interfaces.")
		}
		devs, err := s.runner.ListDevices(req.Interface)
		if err != nil {
			return errorResponse("list_devices_failed", "LIST_DEVICES_FAILED", err.Error(), "Verify the selected interface exists and is not malformed.")
		}
		return ipc.Response{OK: true, Devices: devs, StartedAt: s.startedAt}
	case "captureOnce":
		if resp := validateCaptureRequest(req); resp != nil {
			return *resp
		}
		task := s.newTask(req, s.defaultOutputPath(req.OutputFileName))
		s.registerTask(task)
		ctx, err := s.beginCapture(task)
		if err != nil {
			s.dropTask(task.task.TaskID)
			return errorResponse("capture_busy", "CAPTURE_BUSY", err.Error(), "Wait for the current capture to finish or call usbpcap_stop_capture first.")
		}
		go s.runStartedTask(ctx, task)
		<-task.done
		if task.task.Status == "completed" {
			return ipc.Response{OK: true, PCAPPath: task.task.OutputPath, Triggered: task.task.Triggered, StoreMode: task.task.StoreMode, MatchedDevices: task.task.MatchedDevices, Summary: task.task.Summary, Task: &task.task, StartedAt: s.startedAt}
		}
		if task.task.Status == "no-match" {
			return ipc.Response{OK: true, Message: task.task.Message, Triggered: false, StoreMode: task.task.StoreMode, Task: &task.task, StartedAt: s.startedAt}
		}
		return errorResponse("capture_failed", task.task.ErrorCode, task.task.Message, "Inspect capture task status or run usbpcap_help for examples.")
	case "startCapture":
		if resp := validateCaptureRequest(req); resp != nil {
			return *resp
		}
		task := s.newTask(req, s.defaultOutputPath(req.OutputFileName))
		s.registerTask(task)
		ctx, err := s.beginCapture(task)
		if err != nil {
			s.dropTask(task.task.TaskID)
			return errorResponse("capture_busy", "CAPTURE_BUSY", err.Error(), "Wait for the current capture to finish or call usbpcap_stop_capture first.")
		}
		go s.runStartedTask(ctx, task)
		return ipc.Response{OK: true, Message: "capture task started", Task: &task.task, StartedAt: s.startedAt}
	case "getCaptureTask":
		if strings.TrimSpace(req.TaskID) == "" {
			return errorResponse("invalid_request", "TASK_ID_REQUIRED", "taskId is required", "Pass the taskId returned by startCapture.")
		}
		task := s.taskByID(req.TaskID)
		if task == nil {
			return errorResponse("task_not_found", "TASK_NOT_FOUND", "capture task not found", "Use listCaptureTasks to inspect recent history.")
		}
		return ipc.Response{OK: true, Task: task, StartedAt: s.startedAt}
	case "listCaptureTasks":
		return ipc.Response{OK: true, Tasks: s.listTasks(), StartedAt: s.startedAt}
	case "status":
		return ipc.Response{OK: true, Message: "service is running", ActiveCapture: s.currentCaptureStatus(), Tasks: s.listTasks(), Config: s.configSnapshot(), StartedAt: s.startedAt}
	case "stopCapture":
		if !s.stopCapture("CAPTURE_STOPPED", "capture was stopped", "Retry the capture when ready.") {
			return errorResponse("capture_not_running", "CAPTURE_NOT_RUNNING", "no capture is currently running", "Start a capture before calling stop.")
		}
		return ipc.Response{OK: true, Message: "capture stop requested", ActiveCapture: s.currentCaptureStatus(), StartedAt: s.startedAt}
	case "getConfig":
		return ipc.Response{OK: true, Config: s.configSnapshot(), StartedAt: s.startedAt}
	case "help":
		return ipc.Response{OK: true, Help: defaultHelp(), StartedAt: s.startedAt}
	default:
		return errorResponse("unknown_action", "UNKNOWN_ACTION", req.Action, "Use the MCP tools list or call help.")
	}
}

func defaultHelp() string {
	return strings.TrimSpace(`Actions:
- listInterfaces
- listDevices { interface }
- captureOnce { interface|autoInterface, vendorId, productId, durationSeconds, endpoint, transferType, storeMode, idleTimeoutSeconds, maxFileSizeBytes }
- startCapture { interface|autoInterface, vendorId, productId, durationSeconds, endpoint, transferType, storeMode, idleTimeoutSeconds, maxFileSizeBytes }
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

Discovery:
- Use listInterfaces first.
- Then use listDevices with an explicit interface.

Capture:
- Prefer interface for deterministic capture.
- Use autoInterface only with vendorId/productId filters.
- durationSeconds must be between 0 and 86400 and defaults to 10 when omitted.
- idleTimeoutSeconds and maxFileSizeBytes default to service config when omitted.
- Only one capture runs at a time; use stopCapture to cancel the current capture.

History:
- startCapture returns taskId immediately.
- Use getCaptureTask or listCaptureTasks to inspect current and recent captures.

Trigger mode:
- on-match delays file creation until a matching packet is seen.
- If nothing matches, the response returns triggered=false and no pcap file is produced.`)
}
