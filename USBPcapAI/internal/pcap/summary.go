// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"usbpcap-ai/internal/ipc"
)

type fileHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

type recordHeader struct {
	TSSec   uint32
	TSUsec  uint32
	InclLen uint32
	OrigLen uint32
}

type usbpcapHeader struct {
	HeaderLen uint16
	IRPId     uint64
	Status    uint32
	Function  uint16
	Info      uint8
	Bus       uint16
	Device    uint16
	Endpoint  uint8
	Transfer  uint8
	DataLen   uint32
}

func Summarize(path string) (*ipc.Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	var fh fileHeader
	if err := binary.Read(f, binary.LittleEndian, &fh); err != nil {
		return nil, err
	}
	if fh.MagicNumber != 0xA1B2C3D4 && fh.MagicNumber != 0xD4C3B2A1 {
		return nil, errors.New("unsupported pcap magic")
	}
	if fh.Network != 249 {
		return nil, errors.New("unsupported link type")
	}

	summary := &ipc.Summary{
		SizeBytes: st.Size(),
		TransferTypes: map[string]uint64{
			"control":     0,
			"bulk":        0,
			"interrupt":   0,
			"isochronous": 0,
			"unknown":     0,
		},
		EndpointDistribution: make(map[string]uint64),
		DeviceDistribution:   make(map[string]uint64),
	}

	for {
		var rh recordHeader
		if err := binary.Read(f, binary.LittleEndian, &rh); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		buf := make([]byte, rh.InclLen)
		if _, err := io.ReadFull(f, buf); err != nil {
			return nil, err
		}
		summary.PacketCount++
		tsMillis := uint64(rh.TSSec)*1000 + uint64(rh.TSUsec)/1000
		if summary.FirstPacketTSUnix == 0 {
			summary.FirstPacketTSUnix = int64(tsMillis)
		}
		summary.LastPacketTSUnix = int64(tsMillis)
		if len(buf) < 27 {
			summary.TransferTypes["unknown"]++
			continue
		}
		var uh usbpcapHeader
		uh.HeaderLen = binary.LittleEndian.Uint16(buf[0:2])
		uh.Device = binary.LittleEndian.Uint16(buf[19:21])
		uh.Endpoint = buf[21]
		uh.Transfer = buf[22]
		switch uh.Transfer {
		case 0:
			summary.TransferTypes["isochronous"]++
		case 1:
			summary.TransferTypes["interrupt"]++
		case 2:
			summary.TransferTypes["control"]++
		case 3:
			summary.TransferTypes["bulk"]++
		default:
			summary.TransferTypes["unknown"]++
		}
		epKey := fmt.Sprintf("0x%02x", uh.Endpoint)
		summary.EndpointDistribution[epKey]++
		devKey := fmt.Sprintf("0x%02x", uh.Device)
		summary.DeviceDistribution[devKey]++
	}

	if summary.FirstPacketTSUnix > 0 && summary.LastPacketTSUnix >= summary.FirstPacketTSUnix {
		summary.DurationMS = uint64(summary.LastPacketTSUnix - summary.FirstPacketTSUnix)
	}
	return summary, nil
}
