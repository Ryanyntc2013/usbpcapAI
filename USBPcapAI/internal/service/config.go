// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const ConfigFileName = "config.json"

type Config struct {
	CaptureDir         string `json:"captureDir"`
	CMDPath            string `json:"cmdPath"`
	IdleTimeoutSeconds uint32 `json:"idleTimeoutSeconds,omitempty"`
	MaxFileSizeBytes   int64  `json:"maxFileSizeBytes,omitempty"`
	MaxHistoryTasks    int    `json:"maxHistoryTasks,omitempty"`
	MaxCaptureFiles    int    `json:"maxCaptureFiles,omitempty"`
}

func DefaultConfig(exePath string) Config {
	base := filepath.Dir(exePath)
	return Config{
		CaptureDir:         filepath.Join(base, "captures"),
		CMDPath:            filepath.Join(base, "USBPcapCMD.exe"),
		IdleTimeoutSeconds: 30,
		MaxFileSizeBytes:   100 * 1024 * 1024,
		MaxHistoryTasks:    20,
		MaxCaptureFiles:    50,
	}
}

func ConfigPath(exePath string) string {
	return filepath.Join(filepath.Dir(exePath), ConfigFileName)

}

func LoadConfig(exePath string) (Config, error) {
	path := ConfigPath(exePath)
	defaultCfg := DefaultConfig(exePath)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return defaultCfg, nil
		}
		return Config{}, err
	}

	cfg := defaultCfg
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func SaveConfig(exePath string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := ConfigPath(exePath)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	// Best-effort: restrict ACL to SYSTEM / Administrators / Interactive.
	_ = secureFileACL(path)
	return nil
}

func (c Config) Validate() error {
	if c.CMDPath == "" {
		return errors.New("USBPcapCMD.exe path is empty")
	}
	if c.CaptureDir == "" {
		return errors.New("capture dir is empty")
	}
	if !filepath.IsAbs(c.CMDPath) {
		return errors.New("USBPcapCMD.exe path must be absolute")
	}
	if !strings.EqualFold(filepath.Base(c.CMDPath), "USBPcapCMD.exe") {
		return errors.New("cmdPath must point to USBPcapCMD.exe")
	}
	st, err := os.Stat(c.CMDPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return errors.New("cmdPath must be a file, not a directory")
	}
	if c.IdleTimeoutSeconds > 24*60*60 {
		return errors.New("idleTimeoutSeconds must be <= 86400")
	}
	if c.MaxFileSizeBytes < 0 {
		return errors.New("maxFileSizeBytes must be >= 0")
	}
	if c.MaxHistoryTasks <= 0 {
		return errors.New("maxHistoryTasks must be > 0")
	}
	if c.MaxCaptureFiles <= 0 {
		return errors.New("maxCaptureFiles must be > 0")
	}
	if err := os.MkdirAll(c.CaptureDir, 0o755); err != nil {
		return err
	}
	return nil
}
