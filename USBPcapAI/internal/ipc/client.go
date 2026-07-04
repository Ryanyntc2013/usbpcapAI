// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"time"

	"github.com/Microsoft/go-winio"
)

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
