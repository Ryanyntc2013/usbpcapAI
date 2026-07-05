// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Microsoft/go-winio"
)

// Call sends a request to the USBPcap service via named pipe.
func Call(req Request) (Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, PipeName)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// CallWithAutoService calls the service, auto-launching it in foreground
// mode if the named pipe is not available (no admin required).
func CallWithAutoService(req Request) (Response, error) {
	resp, err := Call(req)
	if err == nil {
		return resp, nil
	}
	// Pipe not available — try to launch the service
	if launchErr := EnsureService(); launchErr != nil {
		return Response{}, fmt.Errorf("service unavailable: %w (auto-launch also failed: %w)", err, launchErr)
	}
	// Retry the call — now the service should be running
	return Call(req)
}
