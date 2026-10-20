package detect

import (
	"fmt"
	"sort"

	"sharaga/internal/models"
)

// Run executes all local heuristic detectors. No external API calls.
func Run(packets []models.PacketRow, summary models.Summary) ([]models.Threat, int) {
	if len(packets) == 0 {
		return []models.Threat{}, 0
	}

	var threats []models.Threat
	threats = append(threats, detectSYNFlood(packets, summary)...)
	threats = append(threats, detectUDPFlood(packets, summary)...)
	threats = append(threats, detectICMPFlood(packets, summary)...)
	threats = append(threats, detectPortScan(packets)...)
	threats = append(threats, detectHostScan(packets)...)
	threats = append(threats, detectDNSAnomalies(packets, summary)...)
	threats = append(threats, detectSuspiciousPorts(packets)...)
	threats = append(threats, detectExfiltration(packets, summary)...)
	threats = append(threats, detectBeaconing(packets)...)
	threats = append(threats, detectNullXmasScan(packets)...)
	threats = append(threats, detectHTTPSuspicious(packets)...)
	threats = append(threats, detectHighPPS(summary)...)

	sort.Slice(threats, func(i, j int) bool {
		return severityRank(threats[i].Severity) > severityRank(threats[j].Severity)
	})

	return threats, score(threats)
}

func score(threats []models.Threat) int {
	if len(threats) == 0 {
		return 0
	}
	total := 0.0
	for _, t := range threats {
		w := float64(severityRank(t.Severity)) * 12
		total += w * t.Confidence
	}
	if total > 100 {
		return 100
	}
	return int(total)
}

func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	default:
		return 1
	}
}

func topKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		out[i] = fmt.Sprintf("%s (%d)", x.k, x.v)
	}
	return out
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
