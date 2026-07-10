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
)

// MaxRecordSize is the maximum allowed incl_len for a single pcap record.
// This prevents OOM on truncated or malicious pcap files.
const MaxRecordSize = 64 * 1024 * 1024 // 64 MiB

// MaxTotalPayloadBytes is the maximum total payload bytes exported/analyzed.
const MaxTotalPayloadBytes = 512 * 1024 * 1024 // 512 MiB

// fileHeader is the pcap file global header.
type fileHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// recordHeader is the per-packet pcap record header.
type recordHeader struct {
	TSSec   uint32
	TSUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// Record holds one parsed pcap record with its USBPcap header fields.
type Record struct {
	TSSec      uint32
	TSUsec     uint32
	InclLen    uint32
	OrigLen    uint32
	Device     uint16
	Endpoint   uint8
	Transfer   uint8
	DataLen    uint32 // declared data length from USBPcap header
	Payload    []byte // payload bytes (after USBPcap header), may be shorter than DataLen
	HeaderLen  uint16 // USBPcap header length from the packet
	ActualLen  uint32 // actual payload bytes captured
}

// Reader provides safe, bounded iteration over USBPcap pcap records.
type Reader struct {
	f        *os.File
	hdr      fileHeader
	buf      []byte
	fileSize int64
}

// OpenReader opens a pcap file and validates it is a USBPcap capture.
func OpenReader(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	var fh fileHeader
	if err := binary.Read(f, binary.LittleEndian, &fh); err != nil {
		f.Close()
		return nil, err
	}
	if fh.MagicNumber != 0xA1B2C3D4 && fh.MagicNumber != 0xD4C3B2A1 {
		f.Close()
		return nil, errors.New("unsupported pcap magic")
	}
	if fh.Network != 249 {
		f.Close()
		return nil, fmt.Errorf("unsupported link type %d: not USBPcap", fh.Network)
	}
	return &Reader{
		f:        f,
		hdr:      fh,
		fileSize: st.Size(),
	}, nil
}

// Close closes the underlying file.
func (r *Reader) Close() error {
	return r.f.Close()
}

// FileSize returns the total file size in bytes.
func (r *Reader) FileSize() int64 { return r.fileSize }

// Next reads the next record. Returns io.EOF when done.
// Returns an error for truncated, oversized, or malformed records.
func (r *Reader) Next() (*Record, error) {
	var rh recordHeader
	if err := binary.Read(r.f, binary.LittleEndian, &rh); err != nil {
		return nil, err
	}
	if rh.InclLen > MaxRecordSize {
		return nil, fmt.Errorf("record incl_len %d exceeds maximum %d", rh.InclLen, MaxRecordSize)
	}
	buf := make([]byte, rh.InclLen)
	if _, err := io.ReadFull(r.f, buf); err != nil {
		return nil, fmt.Errorf("truncated record: %w", err)
	}
	rec := &Record{
		TSSec:   rh.TSSec,
		TSUsec:  rh.TSUsec,
		InclLen: rh.InclLen,
		OrigLen: rh.OrigLen,
	}
	if len(buf) < 27 {
		// Not a valid USBPcap header; return raw record only
		return rec, nil
	}
	rec.HeaderLen = binary.LittleEndian.Uint16(buf[0:2])
	rec.Device = binary.LittleEndian.Uint16(buf[19:21])
	rec.Endpoint = buf[21]
	rec.Transfer = buf[22]
	rec.DataLen = binary.LittleEndian.Uint32(buf[23:27])

	payloadStart := int(rec.HeaderLen)
	if payloadStart < 27 || payloadStart > len(buf) {
		// HeaderLen is out of bounds; treat entire buffer as header-only
		return rec, nil
	}
	payloadEnd := payloadStart + int(rec.DataLen)
	if payloadEnd > len(buf) {
		payloadEnd = len(buf)
	}
	rec.Payload = buf[payloadStart:payloadEnd]
	rec.ActualLen = uint32(len(rec.Payload))
	return rec, nil
}

// SummarizeReader returns a summary using the safe Reader.
func SummarizeReader(path string) (*SummaryData, error) {
	r, err := OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	s := &SummaryData{
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

	var firstTS, lastTS uint64
	var firstSet bool
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		s.PacketCount++
		tsMillis := uint64(rec.TSSec)*1000 + uint64(rec.TSUsec)/1000
		if !firstSet {
			firstTS = tsMillis
			firstSet = true
		}
		lastTS = tsMillis
		if rec.HeaderLen == 0 {
			s.TransferTypes["unknown"]++
			continue
		}
		switch rec.Transfer {
		case 0:
			s.TransferTypes["isochronous"]++
		case 1:
			s.TransferTypes["interrupt"]++
		case 2:
			s.TransferTypes["control"]++
		case 3:
			s.TransferTypes["bulk"]++
		default:
			s.TransferTypes["unknown"]++
		}
		epKey := fmt.Sprintf("0x%02x", rec.Endpoint)
		s.EndpointDistribution[epKey]++
		devKey := fmt.Sprintf("0x%02x", rec.Device)
		s.DeviceDistribution[devKey]++
	}

	if firstSet && lastTS >= firstTS {
		s.DurationMS = lastTS - firstTS
	}
	return s, nil
}

// SummaryData is the raw summary before conversion to ipc.Summary.
type SummaryData struct {
	PacketCount          uint64
	DurationMS           uint64
	TransferTypes        map[string]uint64
	EndpointDistribution map[string]uint64
	DeviceDistribution   map[string]uint64
}