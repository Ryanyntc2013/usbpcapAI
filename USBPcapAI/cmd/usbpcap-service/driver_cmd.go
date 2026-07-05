// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// driverInstall installs the USBPcap driver using pnputil (Win10+) or legacy setupapi.
func driverInstall(exePath string) error {
	if !isAdmin() {
		return fmt.Errorf("driver installation requires Administrator privileges")
	}

	drvDir, err := detectDriverDir(exePath)
	if err != nil {
		return err
	}
	infFile := filepath.Join(drvDir, "USBPcap.inf")
	if _, err := os.Stat(infFile); os.IsNotExist(err) {
		return fmt.Errorf("driver files not found at %s\n  Expected: USBPcap.inf, USBPcap.sys, USBPcap*.cat\n  Build the driver using WDK, then place files in drivers/<os>/<arch>/", drvDir)
	}

	// Check if already installed via pnputil
	if isWin10OrLater() {
		out, _ := exec.Command("pnputil", "/enum-drivers").Output()
		if strings.Contains(string(out), "USBPcap.inf") {
			fmt.Println("WARNING: USBPcap driver appears to be already installed.")
			fmt.Println("  Uninstall first with 'driver-uninstall' if you need to reinstall.")
			return nil
		}
	}

	fmt.Printf("Installing USBPcap driver (%s)...\n", drvDir)
	fmt.Printf("  Driver path: %s\n", drvDir)

	if isWin10OrLater() {
		cmd := exec.Command("pnputil", "/add-driver", infFile, "/install")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("pnputil failed: %w", err)
		}
	} else {
		fmt.Println("  Using legacy setupapi method...")
		cmd := exec.Command("rundll32.exe", "setupapi.dll,InstallHinfSection", "DefaultInstall", "132", infFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}

	fmt.Println("Driver installed. A reboot may be required.")
	fmt.Println("  NOTE: On 64-bit Windows with Secure Boot, enable test signing:")
	fmt.Println("    bcdedit /set testsigning on")
	fmt.Println("    (reboot required)")
	return nil
}

// driverUninstall removes the USBPcap driver.
func driverUninstall(exePath string) error {
	if !isAdmin() {
		return fmt.Errorf("driver uninstallation requires Administrator privileges")
	}

	fmt.Println("Uninstalling USBPcap driver...")

	// Try pnputil first
	out, err := exec.Command("pnputil", "/enum-drivers").Output()
	if err == nil && strings.Contains(string(out), "USBPcap.inf") {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Published Name") && strings.Contains(strings.ToLower(line), "oem") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					pubName := fields[len(fields)-1]
					fmt.Printf("  Removing: %s\n", pubName)
					cmd := exec.Command("pnputil", "/delete-driver", pubName, "/uninstall")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					_ = cmd.Run()
				}
			}
		}
		fmt.Println("Driver uninstalled. Reboot to complete removal.")
		return nil
	}

	// Fallback to legacy method
	drvDir, err := detectDriverDir(exePath)
	if err != nil {
		return fmt.Errorf("driver not found in driver store and local files not available: %w", err)
	}
	infFile := filepath.Join(drvDir, "USBPcap.inf")
	if _, err := os.Stat(infFile); err == nil {
		fmt.Println("  Using legacy setupapi method...")
		cmd := exec.Command("rundll32.exe", "setupapi.dll,InstallHinfSection", "DefaultUninstall", "132", infFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		fmt.Println("Driver uninstalled. Reboot to complete removal.")
	} else {
		fmt.Println("WARNING: Driver files not found locally and not in driver store.")
		fmt.Println("  If you installed via another method, uninstall from there.")
	}
	return nil
}

func detectDriverDir(exePath string) (string, error) {
	base := filepath.Dir(exePath)
	osVer := detectWinVersion()
	arch := "x64"
	if runtime.GOARCH == "386" {
		arch = "x86"
	}
	return filepath.Join(base, "drivers", osVer, arch), nil
}

func detectWinVersion() string {
	major, _, _ := rtlGetVersion()
	if major >= 10 {
		return "win10"
	}
	if major == 6 {
		return "win8"
	}
	return "win7"
}

func isWin10OrLater() bool {
	major, _, _ := rtlGetVersion()
	return major >= 10
}
