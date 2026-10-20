package detect

import (
	"testing"

	"sharaga/internal/models"
)

func TestSYNFloodDetection(t *testing.T) {
	packets := make([]models.PacketRow, 0, 300)
	for i := 0; i < 300; i++ {
		packets = append(packets, models.PacketRow{
			Number: i + 1, TimeRel: float64(i) * 0.001,
			SrcIP: "1.2.3.4", DstIP: "10.0.0.1",
			SrcPort: 40000 + i%1000, DstPort: 80,
			Protocol: "TCP", Length: 60, TCPSyn: true,
		})
	}
	summary := models.Summary{PacketCount: len(packets), DurationSec: 0.3, PPS: 1000}
	threats, score := Run(packets, summary)
	found := false
	for _, th := range threats {
		if th.ID == "ddos-syn-flood" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected syn flood threat, got %#v score=%d", threats, score)
	}
}

func TestPortScanDetection(t *testing.T) {
	packets := make([]models.PacketRow, 0, 60)
	for port := 1; port <= 40; port++ {
		packets = append(packets, models.PacketRow{
			Number: port, TimeRel: float64(port) * 0.01,
			SrcIP: "9.9.9.9", DstIP: "10.0.0.5",
			SrcPort: 50000, DstPort: port,
			Protocol: "TCP", Length: 54, TCPSyn: true,
		})
	}
	summary := models.Summary{PacketCount: len(packets), DurationSec: 1}
	threats, _ := Run(packets, summary)
	found := false
	for _, th := range threats {
		if th.Category == "scan" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected port scan, got %#v", threats)
	}
}
