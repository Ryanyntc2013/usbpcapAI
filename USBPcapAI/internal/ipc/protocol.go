// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package ipc

import "time"

const PipeName = `\\.\pipe\usbpcap-ai-service`

type Request struct {
	Action string `json:"action"`

	Interface         string `json:"interface,omitempty"`
	AutoInterface     bool   `json:"autoInterface,omitempty"`
	VendorID          string `json:"vendorId,omitempty"`
	ProductID         string `json:"productId,omitempty"`
	DurationSeconds   uint32 `json:"durationSeconds,omitempty"`
	CaptureNewDevices bool   `json:"captureNewDevices,omitempty"`
	AppFilter         bool   `json:"appFilter,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	TransferType      string `json:"transferType,omitempty"`
	StoreMode         string `json:"storeMode,omitempty"`
	OutputFileName    string `json:"outputFileName,omitempty"`
	IdleTimeoutSeconds uint32 `json:"idleTimeoutSeconds,omitempty"`
	MaxFileSizeBytes   int64  `json:"maxFileSizeBytes,omitempty"`
	TaskID            string `json:"taskId,omitempty"`
	PCAPPath          string `json:"pcapPath,omitempty"`
	DeviceAddress     *int   `json:"deviceAddress,omitempty"`
	MinDataLen        uint32 `json:"minDataLen,omitempty"`
	Format            string `json:"format,omitempty"`
}

type InterfaceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
}

type DeviceInfo struct {
	Address        uint16 `json:"address"`
	AddressHex     string `json:"addressHex"`
	Port           uint32 `json:"port,omitempty"`
	ParentAddress  uint16 `json:"parentAddress"`
	VendorID       string `json:"vendorId,omitempty"`
	ProductID      string `json:"productId,omitempty"`
	IsHub          bool   `json:"isHub,omitempty"`
	Description    string `json:"description,omitempty"`
}

type MatchedDevice struct {
	Interface string `json:"interface,omitempty"`
	Address   uint16 `json:"address"`
	VendorID  string `json:"vendorId,omitempty"`
	ProductID string `json:"productId,omitempty"`
}

type Summary struct {
	PacketCount          uint64            `json:"packetCount"`
	SizeBytes            int64             `json:"sizeBytes"`
	DurationMS           uint64            `json:"durationMs,omitempty"`
	DroppedPackets       uint64            `json:"droppedPackets,omitempty"`
	TransferTypes        map[string]uint64 `json:"transferTypes,omitempty"`
	EndpointDistribution map[string]uint64 `json:"endpointDistribution,omitempty"`
	DeviceDistribution   map[string]uint64 `json:"deviceDistribution,omitempty"`
	FirstPacketTSUnix    int64             `json:"firstPacketTsUnix,omitempty"`
	LastPacketTSUnix     int64             `json:"lastPacketTsUnix,omitempty"`
}

type CaptureStatus struct {
	Running     bool      `json:"running"`
	Interface   string    `json:"interface,omitempty"`
	OutputPath  string    `json:"outputPath,omitempty"`
	StartedAt   time.Time `json:"startedAt,omitempty"`
	StoreMode   string    `json:"storeMode,omitempty"`
	AutoStopSec uint32    `json:"autoStopSec,omitempty"`
}

type CaptureTask struct {
	TaskID          string         `json:"taskId"`
	Status          string         `json:"status"`
	Interface       string         `json:"interface,omitempty"`
	OutputPath      string         `json:"outputPath,omitempty"`
	StoreMode       string         `json:"storeMode,omitempty"`
	StartedAt       time.Time      `json:"startedAt,omitempty"`
	FinishedAt      time.Time      `json:"finishedAt,omitempty"`
	DurationSeconds uint32         `json:"durationSeconds,omitempty"`
	ErrorCode       string         `json:"errorCode,omitempty"`
	Message         string         `json:"message,omitempty"`
	Hint            string         `json:"hint,omitempty"`
	Triggered       bool           `json:"triggered,omitempty"`
	MatchedDevices  []MatchedDevice `json:"matchedDevices,omitempty"`
	Summary         *Summary       `json:"summary,omitempty"`
}

type NextAction struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

type Response struct {
	OK        bool   `json:"ok"`
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
	Message   string `json:"message,omitempty"`
	Hint      string `json:"hint,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`

	Interfaces         []InterfaceInfo  `json:"interfaces,omitempty"`
	Devices            []DeviceInfo     `json:"devices,omitempty"`
	PCAPPath           string           `json:"pcapPath,omitempty"`
	Triggered          bool             `json:"triggered,omitempty"`
	StoreMode          string           `json:"storeMode,omitempty"`
	MatchedDevices     []MatchedDevice  `json:"matchedDevices,omitempty"`
	Summary            *Summary         `json:"summary,omitempty"`
	Help               string           `json:"help,omitempty"`
	Config             *ConfigSnapshot  `json:"config,omitempty"`
	ActiveCapture      *CaptureStatus   `json:"activeCapture,omitempty"`
	Task               *CaptureTask     `json:"task,omitempty"`
	Tasks              []CaptureTask    `json:"tasks,omitempty"`
	StartedAt          time.Time        `json:"startedAt,omitempty"`
	NormalizedArguments map[string]any  `json:"normalizedArguments,omitempty"`
	NextAction         *NextAction      `json:"nextAction,omitempty"`

	// New structured outputs
	AnalyzeResult    *AnalyzeResult    `json:"analyzeResult,omitempty"`
	ProfileResult    *ProfileResult    `json:"profileResult,omitempty"`
	DiagnosisResult  *DiagnosisResult   `json:"diagnosisResult,omitempty"`
	ExportContent    string            `json:"exportContent,omitempty"`
	ExportPath       string            `json:"exportPath,omitempty"`
}

type ConfigSnapshot struct {
	CaptureDir         string `json:"captureDir"`
	CMDPath            string `json:"cmdPath"`
	PipeName           string `json:"pipeName"`
	IdleTimeoutSeconds uint32 `json:"idleTimeoutSeconds,omitempty"`
	MaxFileSizeBytes   int64  `json:"maxFileSizeBytes,omitempty"`
	MaxHistoryTasks    int    `json:"maxHistoryTasks,omitempty"`
	MaxCaptureFiles    int    `json:"maxCaptureFiles,omitempty"`
	HistoryTaskTTLMinutes int `json:"historyTaskTTLMinutes,omitempty"`
}

// AnalyzeResult holds structured USB traffic analysis output.
type AnalyzeResult struct {
	PCAPPath     string                 `json:"pcapPath"`
	PacketCount  uint64                 `json:"packetCount"`
	DurationMS   uint64                 `json:"durationMs,omitempty"`
	Endpoints    []EndpointStat         `json:"endpoints"`
	PayloadStats *PayloadStats          `json:"payloadStats,omitempty"`
	BytePattern  map[string]uint64      `json:"bytePattern,omitempty"`
	DataLenStats map[string]uint64      `json:"dataLenStats,omitempty"`
}

type EndpointStat struct {
	Endpoint     string `json:"endpoint"`
	Direction    string `json:"direction,omitempty"`
	TransferType string `json:"transferType"`
	PacketCount  uint64 `json:"packetCount"`
	TotalBytes   uint64 `json:"totalBytes"`
	MinDataLen   uint32 `json:"minDataLen,omitempty"`
	MaxDataLen   uint32 `json:"maxDataLen,omitempty"`
	AvgDataLen   uint32 `json:"avgDataLen,omitempty"`
}

type PayloadStats struct {
	TotalPayloadBytes uint64            `json:"totalPayloadBytes"`
	DataLenBuckets    map[string]uint64 `json:"dataLenBuckets"`
	FirstBytePattern  map[string]uint64 `json:"firstBytePattern,omitempty"`
}

// ProfileResult is the output of usbpcap_profile_device.
type ProfileResult struct {
	Device          MatchedDevice          `json:"device"`
	DurationSeconds uint32                 `json:"durationSeconds"`
	PacketCount     uint64                 `json:"packetCount"`
	Endpoints       []EndpointStat         `json:"endpoints"`
	Recommended     map[string]any         `json:"recommended,omitempty"`
}

// DiagnosisResult is the output of usbpcap_diagnose_capture.
type DiagnosisResult struct {
	Diagnosis     string         `json:"diagnosis"`
	Confidence    float64        `json:"confidence"`
	Recommendation string       `json:"recommendation"`
	NextAction    *NextAction    `json:"nextAction,omitempty"`
}

// ExportRequest is the input for usbpcap_export_data (server-side).
type ExportRequest struct {
	PCAPPath      string `json:"pcapPath"`
	DeviceAddress uint16 `json:"deviceAddress"`
	Endpoint      string `json:"endpoint"`
	MinDataLen    uint32 `json:"minDataLen"`
	Format        string `json:"format"`
	OutputPath    string `json:"outputPath"`
}
