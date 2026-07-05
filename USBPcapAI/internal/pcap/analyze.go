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

func Analyze(path string, deviceAddr *uint16) (*ipc.AnalyzeResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var fh fileHeader
	if err := binary.Read(f, binary.LittleEndian, &fh); err != nil {
		return nil, err
	}
	if fh.MagicNumber != 0xA1B2C3D4 && fh.MagicNumber != 0xD4C3B2A1 {
		return nil, errors.New("unsupported pcap magic")
	}
	if fh.Network != 249 {
		return nil, errors.New("unsupported link type: not USBPcap")
	}

	endpointMap := make(map[string]*endpointAccum)
	var firstTS, lastTS uint64
	var firstSet bool
	totalPayloadBytes := uint64(0)
	dataLenBuckets := make(map[string]uint64)
	firstBytePattern := make(map[string]uint64)

	dataLenCounted := make(map[uint32]uint64)

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

		tsMillis := uint64(rh.TSSec)*1000 + uint64(rh.TSUsec)/1000
		if !firstSet {
			firstTS = tsMillis
			firstSet = true
		}
		lastTS = tsMillis

		if len(buf) < 27 {
			continue
		}

		device := binary.LittleEndian.Uint16(buf[19:21])
		if deviceAddr != nil && device != *deviceAddr {
			continue
		}

		endpoint := buf[21]
		transfer := buf[22]
		dataLen := binary.LittleEndian.Uint32(buf[23:27])

		epKey := fmt.Sprintf("0x%02x", endpoint)
		acc, ok := endpointMap[epKey]
		if !ok {
			dir := "OUT"
			if endpoint&0x80 != 0 {
				dir = "IN"
			}
			t := transferTypeName(transfer)
			acc = &endpointAccum{
				endpoint:  epKey,
				direction: dir,
				transType: t,
			}
			endpointMap[epKey] = acc
		}
		acc.packets++
		acc.totalBytes += uint64(dataLen)
		if acc.minDataLen == 0 || dataLen < acc.minDataLen {
			acc.minDataLen = dataLen
		}
		if dataLen > acc.maxDataLen {
			acc.maxDataLen = dataLen
		}

		totalPayloadBytes += uint64(dataLen)
		dataLenCounted[dataLen]++

		// First byte of payload (after the 27-byte USBPcap header)
		payloadStart := int(binary.LittleEndian.Uint16(buf[0:2]))
		if payloadStart >= 27 && payloadStart+1 < len(buf) {
			firstByte := buf[payloadStart]
			fbKey := fmt.Sprintf("0x%02x", firstByte)
			firstBytePattern[fbKey]++
		}
	}

	if len(endpointMap) == 0 {
		return &ipc.AnalyzeResult{
			PCAPPath:    path,
			PacketCount: 0,
			Endpoints:   []ipc.EndpointStat{},
		}, nil
	}

	endpoints := make([]ipc.EndpointStat, 0, len(endpointMap))
	for _, acc := range endpointMap {
		avg := uint32(0)
		if acc.packets > 0 {
			avg = uint32(acc.totalBytes / uint64(acc.packets))
		}
		endpoints = append(endpoints, ipc.EndpointStat{
			Endpoint:     acc.endpoint,
			Direction:    acc.direction,
			TransferType: acc.transType,
			PacketCount:  acc.packets,
			TotalBytes:   acc.totalBytes,
			MinDataLen:   acc.minDataLen,
			MaxDataLen:   acc.maxDataLen,
			AvgDataLen:   avg,
		})
	}

	// Build dataLen buckets (grouped by ranges)
	for length, count := range dataLenCounted {
		bucket := dataLenBucket(length)
		dataLenBuckets[bucket] += count
	}
	// Build dataLenStats
	dataLenStats := make(map[string]uint64)
	for k, v := range dataLenCounted {
		dataLenStats[fmt.Sprintf("%d", k)] = v
	}

	durationMs := uint64(0)
	if firstSet && lastTS >= firstTS {
		durationMs = lastTS - firstTS
	}

	return &ipc.AnalyzeResult{
		PCAPPath:    path,
		PacketCount: uint64(len(endpointMap)),
		DurationMS: durationMs,
		Endpoints:   endpoints,
		PayloadStats: &ipc.PayloadStats{
			TotalPayloadBytes: totalPayloadBytes,
			DataLenBuckets:    dataLenBuckets,
			FirstBytePattern:  firstBytePattern,
		},
		DataLenStats: dataLenStats,
		BytePattern:  firstBytePattern,
	}, nil
}

// ExportPayload extracts payload data from pcap for a specific device+endpoint.
// Returns a slice of hex-encoded payload strings per packet.
func ExportPayload(path string, deviceAddress uint16, endpoint string, minDataLen uint32) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var fh fileHeader
	if err := binary.Read(f, binary.LittleEndian, &fh); err != nil {
		return nil, err
	}
	if fh.MagicNumber != 0xA1B2C3D4 && fh.MagicNumber != 0xD4C3B2A1 {
		return nil, errors.New("unsupported pcap magic")
	}
	if fh.Network != 249 {
		return nil, errors.New("unsupported link type: not USBPcap")
	}

	epBytes := parseEndpoint(endpoint)
	var results []string

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
		if len(buf) < 27 {
			continue
		}
		device := binary.LittleEndian.Uint16(buf[19:21])
		epThis := buf[21]
		if device != deviceAddress {
			continue
		}
		if epBytes != nil && epThis != *epBytes {
			continue
		}
		dataLen := binary.LittleEndian.Uint32(buf[23:27])
		if dataLen < minDataLen {
			continue
		}
		payloadStart := int(binary.LittleEndian.Uint16(buf[0:2]))
		if payloadStart < 27 || payloadStart >= len(buf) {
			continue
		}
		payload := buf[payloadStart : payloadStart+int(dataLen)]
		if uint32(len(payload)) > dataLen {
			payload = payload[:dataLen]
		}
		if uint32(len(payload)) < minDataLen {
			continue
		}
		hexStr := fmt.Sprintf("%x", payload)
		results = append(results, hexStr)
	}
	return results, nil
}

type endpointAccum struct {
	endpoint  string
	direction string
	transType string
	packets   uint64
	totalBytes uint64
	minDataLen uint32
	maxDataLen uint32
}

func transferTypeName(t byte) string {
	switch t {
	case 0:
		return "isochronous"
	case 1:
		return "interrupt"
	case 2:
		return "control"
	case 3:
		return "bulk"
	case 0xFE:
		return "irp_info"
	case 0xFF:
		return "unknown"
	default:
		return "unknown"
	}
}

func dataLenBucket(length uint32) string {
	switch {
	case length <= 8:
		return "1-8"
	case length <= 64:
		return "9-64"
	case length <= 256:
		return "65-256"
	case length <= 512:
		return "257-512"
	case length <= 1024:
		return "513-1024"
	case length <= 2048:
		return "1025-2048"
	case length <= 4096:
		return "2049-4096"
	default:
		return "4097+"
	}
}

func parseEndpoint(s string) *byte {
	if s == "" {
		return nil
	}
	raw := s
	if len(raw) > 2 && (raw[:2] == "0x" || raw[:2] == "0X") {
		raw = raw[2:]
	}
	if len(raw) > 2 {
		return nil
	}
	var v byte
	for _, c := range raw {
		v *= 16
		switch {
		case c >= '0' && c <= '9':
			v += byte(c - '0')
		case c >= 'a' && c <= 'f':
			v += byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v += byte(c - 'A' + 10)
		default:
			return nil
		}
	}
	return &v
}
