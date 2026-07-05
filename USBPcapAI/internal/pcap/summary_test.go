// Copyright (c) 2026 https://github.com/Ryanyntc2013
//
// SPDX-License-Identifier: BSD-2-Clause

package pcap

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSummarizeUSBPcapFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.pcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	fh := fileHeader{
		MagicNumber:  0xA1B2C3D4,
		VersionMajor: 2,
		VersionMinor: 4,
		SnapLen:      65535,
		Network:      249,
	}
	if err := binary.Write(f, binary.LittleEndian, &fh); err != nil {
		t.Fatal(err)
	}

	writePacket := func(tsSec, tsUsec uint32, device uint16, endpoint byte, transfer byte) {
		t.Helper()
		payload := make([]byte, 27)
		binary.LittleEndian.PutUint16(payload[0:2], 27)
		binary.LittleEndian.PutUint16(payload[19:21], device)
		payload[21] = endpoint
		payload[22] = transfer
		rh := recordHeader{TSSec: tsSec, TSUsec: tsUsec, InclLen: uint32(len(payload)), OrigLen: uint32(len(payload))}
		if err := binary.Write(f, binary.LittleEndian, &rh); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(payload); err != nil {
			t.Fatal(err)
		}
	}

	writePacket(10, 0, 7, 0x81, 2)
	writePacket(10, 500000, 8, 0x02, 3)

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	summary, err := Summarize(path)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PacketCount != 2 {
		t.Fatalf("PacketCount=%d, want 2", summary.PacketCount)
	}
	if summary.TransferTypes["control"] != 1 {
		t.Fatalf("control=%d, want 1", summary.TransferTypes["control"])
	}
	if summary.TransferTypes["bulk"] != 1 {
		t.Fatalf("bulk=%d, want 1", summary.TransferTypes["bulk"])
	}
	if summary.DurationMS != 500 {
		t.Fatalf("DurationMS=%d, want 500", summary.DurationMS)
	}
	if summary.EndpointDistribution["0x81"] != 1 {
		t.Fatalf("endpoint 0x81=%d, want 1", summary.EndpointDistribution["0x81"])
	}
	if summary.EndpointDistribution["0x02"] != 1 {
		t.Fatalf("endpoint 0x02=%d, want 1", summary.EndpointDistribution["0x02"])
	}
	if summary.DeviceDistribution["0x07"] != 1 {
		t.Fatalf("device 0x07=%d, want 1", summary.DeviceDistribution["0x07"])
	}
	if summary.DeviceDistribution["0x08"] != 1 {
		t.Fatalf("device 0x08=%d, want 1", summary.DeviceDistribution["0x08"])
	}
}

func TestSummarizeRejectsNonUSBPcap(t *testing.T) {
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

	if _, err := Summarize(path); err == nil {
		t.Fatal("expected unsupported link type error")
	}
}
