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
}

type InterfaceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
}

type DeviceInfo struct {
	Address        uint16 `json:"address"`
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
	Triggered       bool           `json:"triggered,omitempty"`
	MatchedDevices  []MatchedDevice `json:"matchedDevices,omitempty"`
	Summary         *Summary       `json:"summary,omitempty"`
}

type Response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
	Message   string `json:"message,omitempty"`
	Hint      string `json:"hint,omitempty"`

	Interfaces     []InterfaceInfo `json:"interfaces,omitempty"`
	Devices        []DeviceInfo    `json:"devices,omitempty"`
	PCAPPath       string          `json:"pcapPath,omitempty"`
	Triggered      bool            `json:"triggered,omitempty"`
	StoreMode      string          `json:"storeMode,omitempty"`
	MatchedDevices []MatchedDevice `json:"matchedDevices,omitempty"`
	Summary        *Summary        `json:"summary,omitempty"`
	Help           string          `json:"help,omitempty"`
	Config         *ConfigSnapshot `json:"config,omitempty"`
	ActiveCapture  *CaptureStatus  `json:"activeCapture,omitempty"`
	Task           *CaptureTask    `json:"task,omitempty"`
	Tasks          []CaptureTask   `json:"tasks,omitempty"`
	StartedAt      time.Time       `json:"startedAt,omitempty"`
}

type ConfigSnapshot struct {
	CaptureDir         string `json:"captureDir"`
	CMDPath            string `json:"cmdPath"`
	PipeName           string `json:"pipeName"`
	IdleTimeoutSeconds uint32 `json:"idleTimeoutSeconds,omitempty"`
	MaxFileSizeBytes   int64  `json:"maxFileSizeBytes,omitempty"`
	MaxHistoryTasks    int    `json:"maxHistoryTasks,omitempty"`
	MaxCaptureFiles    int    `json:"maxCaptureFiles,omitempty"`
}
