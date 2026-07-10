// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package pcap

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"usbpcap-ai/internal/ipc"
)

func Analyze(path string, deviceAddr *uint16) (*ipc.AnalyzeResult, error) {
	r, err := OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	type epKey struct {
		endpoint string
		device   uint16
	}
	endpointMap := make(map[epKey]*endpointAccum)
	var firstTS, lastTS uint64
	var firstSet bool
	var totalPackets uint64
	totalPayloadBytes := uint64(0)
	dataLenCounted := make(map[uint32]uint64)
	firstBytePattern := make(map[string]uint64)

	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		totalPackets++
		tsMillis := uint64(rec.TSSec)*1000 + uint64(rec.TSUsec)/1000
		if !firstSet {
			firstTS = tsMillis
			firstSet = true
		}
		lastTS = tsMillis

		if rec.HeaderLen == 0 {
			continue
		}

		if deviceAddr != nil && rec.Device != *deviceAddr {
			continue
		}

		key := epKey{
			endpoint: fmt.Sprintf("0x%02x", rec.Endpoint),
			device:   rec.Device,
		}
		acc, ok := endpointMap[key]
		if !ok {
			dir := "OUT"
			if rec.Endpoint&0x80 != 0 {
				dir = "IN"
			}
			t := transferTypeName(rec.Transfer)
			acc = &endpointAccum{
				endpoint:  key.endpoint,
				device:    key.device,
				direction: dir,
				transType: t,
			}
			endpointMap[key] = acc
		}
		acc.packets++
		acc.totalBytes += uint64(rec.ActualLen)
		if acc.minDataLen == 0 || rec.ActualLen < acc.minDataLen {
			acc.minDataLen = rec.ActualLen
		}
		if rec.ActualLen > acc.maxDataLen {
			acc.maxDataLen = rec.ActualLen
		}

		totalPayloadBytes += uint64(rec.ActualLen)
		dataLenCounted[rec.ActualLen]++

		// First byte of payload
		if len(rec.Payload) > 0 {
			firstByte := rec.Payload[0]
			fbKey := fmt.Sprintf("0x%02x", firstByte)
			firstBytePattern[fbKey]++
		}
	}

	if len(endpointMap) == 0 {
		return &ipc.AnalyzeResult{
			PCAPPath:    path,
			PacketCount: totalPackets,
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
	// Sort by endpoint for stable output
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Endpoint != endpoints[j].Endpoint {
			return endpoints[i].Endpoint < endpoints[j].Endpoint
		}
		return endpoints[i].Direction < endpoints[j].Direction
	})

	// Build dataLen buckets
	dataLenBuckets := make(map[string]uint64)
	for length, count := range dataLenCounted {
		bucket := dataLenBucket(length)
		dataLenBuckets[bucket] += count
	}
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
		PacketCount: totalPackets,
		DurationMS:  durationMs,
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
// Uses the safe Reader with size limits to prevent OOM on malformed files.
// Returns hex-encoded payload strings. Limited to 10000 payloads and 64 MiB total.
func ExportPayload(path string, deviceAddress uint16, endpoint string, minDataLen uint32) ([]string, error) {
	const maxPayloads = 10000
	const maxTotalBytes = 64 * 1024 * 1024

	r, err := OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	epBytes := parseEndpoint(endpoint)
	var results []string
	var totalBytes int

	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if rec.HeaderLen == 0 || rec.Device != deviceAddress {
			continue
		}
		if epBytes != nil && rec.Endpoint != *epBytes {
			continue
		}
		if rec.ActualLen < minDataLen {
			continue
		}
		hexStr := fmt.Sprintf("%x", rec.Payload)
		results = append(results, hexStr)
		totalBytes += len(hexStr)

		if len(results) >= maxPayloads || totalBytes >= maxTotalBytes {
			break
		}
	}
	return results, nil
}

type endpointAccum struct {
	endpoint   string
	device     uint16
	direction  string
	transType  string
	packets    uint64
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
