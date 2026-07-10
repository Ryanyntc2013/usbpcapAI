// Command: go run ./cmd/pcap-report/ <pcap_path> <device_addr>
// Produces a structured JSON analysis report of USB HID mouse traffic.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"usbpcap-ai/internal/pcap"
)

type Report struct {
	PCAPPath    string            `json:"pcapPath"`
	DeviceAddr  uint16            `json:"deviceAddress"`
	PacketCount uint64            `json:"packetCount"`
	DurationMS  uint64            `json:"durationMs"`
	Endpoints   []EndpointBlock   `json:"endpoints"`
	Samples     []SamplePayload   `json:"samples"`
	Summary     MouseEventSummary `json:"summary"`
}

type EndpointBlock struct {
	Endpoint     string `json:"endpoint"`
	Direction    string `json:"direction"`
	TransferType string `json:"transferType"`
	PacketCount  uint64 `json:"packetCount"`
	TotalBytes   uint64 `json:"totalBytes"`
	AvgDataLen   uint32 `json:"avgDataLen"`
}

type SamplePayload struct {
	Index    int    `json:"idx"`
	Hex      string `json:"hex"`
	Len      int    `json:"len"`
	Buttons  uint8  `json:"btn"`
	DX       int16  `json:"dx"`
	DY       int16  `json:"dy"`
	Wheel    int8   `json:"wheel"`
	Desc     string `json:"desc"`
}

type MouseEventSummary struct {
	TotalPayloads  int            `json:"total"`
	Idle           int            `json:"idle"`
	Move           int            `json:"move"`
	Clicks         int            `json:"clicks"`
	Scrolls        int            `json:"scrolls"`
	MaxDX          int            `json:"maxDx"`
	MaxDY          int            `json:"maxDy"`
	LenDist        map[string]int `json:"lenDist"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: pcap-report <pcap_path> <device_addr>\n")
		os.Exit(1)
	}
	path := os.Args[1]
	addr, _ := strconv.ParseUint(os.Args[2], 0, 16)
	devAddr := uint16(addr)

	result, err := pcap.Analyze(path, &devAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Analyze error: %v\n", err)
		os.Exit(1)
	}

	var mainEP string
	for _, ep := range result.Endpoints {
		if ep.Direction == "IN" && ep.PacketCount > 0 {
			mainEP = ep.Endpoint
			break
		}
	}

	rawPayloads, _ := pcap.ExportPayload(path, devAddr, mainEP, 0)

	report := Report{
		PCAPPath:    path,
		DeviceAddr:  devAddr,
		PacketCount: result.PacketCount,
		DurationMS:  result.DurationMS,
	}

	for _, ep := range result.Endpoints {
		report.Endpoints = append(report.Endpoints, EndpointBlock{
			Endpoint: ep.Endpoint, Direction: ep.Direction,
			TransferType: ep.TransferType, PacketCount: ep.PacketCount,
			TotalBytes: ep.TotalBytes, AvgDataLen: ep.AvgDataLen,
		})
	}

	evt := MouseEventSummary{
		TotalPayloads: len(rawPayloads),
		LenDist:       map[string]int{},
	}

	limit := len(rawPayloads)
	if limit > 60 { limit = 60 }
	for i := 0; i < limit; i++ {
		sp := SamplePayload{Index: i, Hex: rawPayloads[i], Len: len(rawPayloads[i]) / 2}
		parsePayload(rawPayloads[i], &sp, &evt)
		report.Samples = append(report.Samples, sp)
		lkey := fmt.Sprintf("%d", sp.Len)
		evt.LenDist[lkey]++
	}
	report.Summary = evt

	b, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(b))
}

func parsePayload(hex string, sp *SamplePayload, evt *MouseEventSummary) {
	if len(hex) < 2 { sp.Desc = "empty"; return }
	raw := hexToBytes(hex)

	sp.Buttons = raw[0]
	if len(raw) >= 3 {
		sp.DX = int16(binary.LittleEndian.Uint16(raw[1:3]))
	}
	if len(raw) >= 5 {
		sp.DY = int16(binary.LittleEndian.Uint16(raw[3:5]))
	}
	if len(raw) >= 6 {
		sp.Wheel = int8(raw[5])
	}

	parts := []string{}
	if raw[0] != 0 {
		parts = append(parts, fmt.Sprintf("BTN=0x%02x", raw[0]))
		evt.Clicks++
	}
	if sp.DX != 0 || sp.DY != 0 {
		parts = append(parts, fmt.Sprintf("d(%+d,%+d)", sp.DX, sp.DY))
		evt.Move++
		if adx := abs16(sp.DX); adx > evt.MaxDX { evt.MaxDX = adx }
		if ady := abs16(sp.DY); ady > evt.MaxDY { evt.MaxDY = ady }
	}
	if len(raw) >= 6 && raw[5] != 0 {
		parts = append(parts, fmt.Sprintf("WHL=%+d", sp.Wheel))
		evt.Scrolls++
	}
	if len(parts) == 0 { parts = append(parts, "idle"); evt.Idle++ }
	sp.Desc = strings.Join(parts, " ")
}

func hexToBytes(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		v, _ := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		b[i] = byte(v)
	}
	return b
}

func abs16(x int16) int {
	if x < 0 { return int(-x) }
	return int(x)
}
