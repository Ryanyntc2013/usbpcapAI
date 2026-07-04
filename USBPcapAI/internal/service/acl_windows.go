// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package service

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// secureFileACL restricts the file DACL to:
//
//	SYSTEM         – full access
//	Administrators – full access
//	Interactive    – generic read + execute
//
// Owner / group / SACL are left untouched.
func secureFileACL(path string) error {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;IU)"

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("SecurityDescriptorFromString: %w", err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("sd.DACL: %w", err)
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}