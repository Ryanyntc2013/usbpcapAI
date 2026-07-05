// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package pcap

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"usbpcap-ai/internal/ipc"
)

func TestAnalyzeBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	fh := fileHeader{
		MagicNumber:  0xA1B2C3D4,
		VersionMajor: 2, VersionMinor: 4,
		SnapLen: 65535, Network: 249,
	}
	if err := binary.Write(f, binary.LittleEndian, &fh); err != nil {
		t.Fatal(err)
	}

	writePacket := func(tsSec, tsUsec uint32, device uint16, endpoint byte, transfer byte, dataLen uint32) {
		t.Helper()
		payloadLen := 27 + int(dataLen)
		payload := make([]byte, payloadLen)
		binary.LittleEndian.PutUint16(payload[0:2], 27) // headerLen
		binary.LittleEndian.PutUint16(payload[19:21], device)
		payload[21] = endpoint
		payload[22] = transfer
		binary.LittleEndian.PutUint32(payload[23:27], dataLen)
		// Fill payload data
		for i := 27; i < payloadLen; i++ {
			payload[i] = byte(i)
		}
		rh := recordHeader{
			TSSec: tsSec, TSUsec: tsUsec,
			InclLen: uint32(payloadLen), OrigLen: uint32(payloadLen),
		}
		if err := binary.Write(f, binary.LittleEndian, &rh); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(payload); err != nil {
			t.Fatal(err)
		}
	}

	// Two bulk IN packets from device 7
	writePacket(10, 0, 7, 0x81, 3, 512)
	writePacket(10, 500000, 7, 0x81, 3, 2048)
	// One control OUT packet from device 7
	writePacket(11, 0, 7, 0x00, 2, 8)
	// One bulk IN packet from device 8 (different)
	writePacket(11, 100000, 8, 0x82, 3, 64)

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := Analyze(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.PacketCount == 0 {
		t.Fatal("expected packets")
	}

	// Verify endpoint breakdown
	epMap := make(map[string]ipc.EndpointStat)
	for _, ep := range result.Endpoints {
		epMap[ep.Endpoint] = ep
	}

	ep81, ok := epMap["0x81"]
	if !ok {
		t.Fatal("endpoint 0x81 not found")
	}
	if ep81.Direction != "IN" {
		t.Fatalf("ep81 direction=%q, want IN", ep81.Direction)
	}
	if ep81.TransferType != "bulk" {
		t.Fatalf("ep81 transfer=%q, want bulk", ep81.TransferType)
	}
	if ep81.PacketCount != 2 {
		t.Fatalf("ep81 packets=%d, want 2", ep81.PacketCount)
	}
	if ep81.TotalBytes != 512+2048 {
		t.Fatalf("ep81 totalBytes=%d, want %d", ep81.TotalBytes, uint64(512+2048))
	}

	ep00, ok := epMap["0x00"]
	if !ok {
		t.Fatal("endpoint 0x00 not found")
	}
	if ep00.Direction != "OUT" {
		t.Fatalf("ep00 direction=%q, want OUT", ep00.Direction)
	}
	if ep00.TransferType != "control" {
		t.Fatalf("ep00 transfer=%q, want control", ep00.TransferType)
	}

	// Test with device filter
	filteredAddr := uint16(7)
	filtered, err := Analyze(path, &filteredAddr)
	if err != nil {
		t.Fatal(err)
	}
	if filtered.PacketCount == 0 {
		t.Fatal("expected filtered packets")
	}
}

func TestAnalyzeRejectsNonUSBPcap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	fh := fileHeader{MagicNumber: 0xA1B2C3D4, VersionMajor: 2, VersionMinor: 4, SnapLen: 65535, Network: 1}
	if err := binary.Write(f, binary.LittleEndian, &fh); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := Analyze(path, nil); err == nil {
		t.Fatal("expected error for non-USBPcap pcap")
	}
}

func TestExportPayloadBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	fh := fileHeader{
		MagicNumber:  0xA1B2C3D4,
		VersionMajor: 2, VersionMinor: 4,
		SnapLen: 65535, Network: 249,
	}
	if err := binary.Write(f, binary.LittleEndian, &fh); err != nil {
		t.Fatal(err)
	}

	// One packet with known payload
	payloadLen := 27 + 8
	payload := make([]byte, payloadLen)
	binary.LittleEndian.PutUint16(payload[0:2], 27)
	binary.LittleEndian.PutUint16(payload[19:21], 7)
	payload[21] = 0x81
	payload[22] = 3
	binary.LittleEndian.PutUint32(payload[23:27], 8)
	payload[27] = 0xAA
	payload[28] = 0xBB
	payload[29] = 0xCC
	payload[30] = 0xDD
	payload[31] = 0x11
	payload[32] = 0x22
	payload[33] = 0x33
	payload[34] = 0x44

	rh := recordHeader{TSSec: 10, TSUsec: 0, InclLen: uint32(payloadLen), OrigLen: uint32(payloadLen)}
	if err := binary.Write(f, binary.LittleEndian, &rh); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	results, err := ExportPayload(path, 7, "0x81", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d payloads, want 1", len(results))
	}
	if results[0] != "aabbccdd11223344" {
		t.Fatalf("payload=%q, want aabbccdd11223344", results[0])
	}

	// Test filter by minDataLen
	results, err = ExportPayload(path, 7, "0x81", 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results with minDataLen=16, got %d", len(results))
	}

	// Test device address mismatch
	results, err = ExportPayload(path, 99, "0x81", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results for wrong device")
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		input string
		want  byte
		ok    bool
	}{
		{"0x81", 0x81, true},
		{"81", 0x81, true},
		{"0x00", 0x00, true},
		{"", 0, false},
		{"0x1a86", 0, false}, // too long
	}
	for _, tt := range tests {
		result := parseEndpoint(tt.input)
		if tt.ok {
			if result == nil {
				t.Fatalf("parseEndpoint(%q)=nil, want %02x", tt.input, tt.want)
			}
			if *result != tt.want {
				t.Fatalf("parseEndpoint(%q)=%02x, want %02x", tt.input, *result, tt.want)
			}
		} else {
			if result != nil {
				t.Fatalf("parseEndpoint(%q)=%02x, want nil", tt.input, *result)
			}
		}
	}
}

func TestDataLenBucket(t *testing.T) {
	tests := []struct {
		length uint32
		want   string
	}{
		{4, "1-8"},
		{64, "9-64"},
		{128, "65-256"},
		{512, "257-512"},
		{600, "513-1024"},
		{2048, "1025-2048"},
		{3000, "2049-4096"},
		{5000, "4097+"},
	}
	for _, tt := range tests {
		got := dataLenBucket(tt.length)
		if got != tt.want {
			t.Fatalf("dataLenBucket(%d)=%q, want %q", tt.length, got, tt.want)
		}
	}
}
