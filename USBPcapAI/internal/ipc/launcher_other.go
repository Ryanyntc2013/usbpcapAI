// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

//go:build !windows

package ipc

func assignToKillOnCloseJob(pid int) (uintptr, error) {
	return 0, nil
}
