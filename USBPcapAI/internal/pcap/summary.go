// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package pcap

import (
	"os"

	"usbpcap-ai/internal/ipc"
)

func Summarize(path string) (*ipc.Summary, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	sd, err := SummarizeReader(path)
	if err != nil {
		return nil, err
	}
	summary := &ipc.Summary{
		PacketCount:          sd.PacketCount,
		SizeBytes:            st.Size(),
		DurationMS:           sd.DurationMS,
		TransferTypes:        sd.TransferTypes,
		EndpointDistribution: sd.EndpointDistribution,
		DeviceDistribution:   sd.DeviceDistribution,
	}
	return summary, nil
}
