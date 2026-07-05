// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func rtlGetVersion() (major, minor, build uint32) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procRtlGetVersion := ntdll.NewProc("RtlGetVersion")
	type osVersionInfoExW struct {
		OSVersionInfoSize uint32
		MajorVersion      uint32
		MinorVersion      uint32
		BuildNumber       uint32
		PlatformId        uint32
		CSDVersion        [128]uint16
		ServicePackMajor  uint16
		ServicePackMinor  uint16
		SuiteMask         uint16
		ProductType       byte
		Reserved          byte
	}
	var ovi osVersionInfoExW
	ovi.OSVersionInfoSize = uint32(unsafe.Sizeof(ovi))
	status, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&ovi)))
	if status != 0 {
		return 10, 0, 0
	}
	return ovi.MajorVersion, ovi.MinorVersion, ovi.BuildNumber
}

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.GetCurrentProcessToken()
	isMember, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return isMember
}
