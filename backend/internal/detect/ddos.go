package detect

import (
	"fmt"
	"strings"

	"sharaga/internal/models"
)

func detectSYNFlood(packets []models.PacketRow, summary models.Summary) []models.Threat {
	synOnly := 0
	synAck := 0
	bySrc := map[string]int{}
	byDst := map[string]int{}

	for _, p := range packets {
		if !p.TCPSyn {
			continue
		}
		if p.TCPAck {
			synAck++
			continue
		}
		synOnly++
		if p.SrcIP != "" {
			bySrc[p.SrcIP]++
		}
		if p.DstIP != "" {
			byDst[p.DstIP]++
		}
	}

	if synOnly < 50 {
		return nil
	}
	ratio := float64(synOnly)
	if synAck > 0 {
		ratio = float64(synOnly) / float64(synAck)
	} else {
		ratio = float64(synOnly)
	}

	// classic SYN flood: many SYN, few SYN-ACK
	if ratio < 5 && synOnly < 200 {
		return nil
	}

	sev := models.SeverityMedium
	conf := 0.65
	if synOnly >= 500 || ratio >= 20 {
		sev = models.SeverityHigh
		conf = 0.85
	}
	if synOnly >= 2000 || (summary.PPS > 500 && ratio >= 10) {
		sev = models.SeverityCritical
		conf = 0.95
	}

	return []models.Threat{{
		ID:       "ddos-syn-flood",
		Category: "ddos",
		Title:    "Возможный SYN flood",
		Description: fmt.Sprintf(
			"Обнаружено %d SYN без ACK при %d SYN-ACK (соотношение ≈ %.1f). Характерно для TCP SYN flood / half-open атак.",
			synOnly, synAck, ratio,
		),
		Severity:   sev,
		Confidence: conf,
		Indicators: []string{
			fmt.Sprintf("syn_without_ack=%d", synOnly),
			fmt.Sprintf("syn_ack=%d", synAck),
			fmt.Sprintf("ratio=%.1f", ratio),
		},
		Sources: keys(bySrc),
		Targets: keys(byDst),
		Count:   synOnly,
	}}
}

func detectUDPFlood(packets []models.PacketRow, summary models.Summary) []models.Threat {
	udp := 0
	byDst := map[string]int{}
	bySrc := map[string]int{}
	byPort := map[int]int{}

	for _, p := range packets {
		up := strings.ToUpper(p.Protocol)
		if up != "UDP" && !strings.Contains(up, "QUIC") {
			continue
		}
		udp++
		bySrc[p.SrcIP]++
		byDst[p.DstIP]++
		byPort[p.DstPort]++
	}

	if udp < 200 {
		return nil
	}
	share := float64(udp) / float64(summary.PacketCount)
	if share < 0.6 && udp < 1000 {
		return nil
	}

	sev := models.SeverityMedium
	conf := 0.6
	if udp >= 1000 || share >= 0.8 {
		sev = models.SeverityHigh
		conf = 0.8
	}
	if summary.PPS > 800 && share >= 0.7 {
		sev = models.SeverityCritical
		conf = 0.9
	}

	portHints := make([]string, 0, 3)
	for port, c := range byPort {
		if c > udp/3 {
			portHints = append(portHints, fmt.Sprintf("dst_port_%d=%d", port, c))
		}
	}

	return []models.Threat{{
		ID:       "ddos-udp-flood",
		Category: "ddos",
		Title:    "Возможный UDP flood",
		Description: fmt.Sprintf(
			"%d UDP-пакетов (%.0f%% захвата). Высокая доля UDP к одним целям типична для UDP flood / amplification.",
			udp, share*100,
		),
		Severity:   sev,
		Confidence: conf,
		Indicators: append([]string{
			fmt.Sprintf("udp_packets=%d", udp),
			fmt.Sprintf("share=%.0f%%", share*100),
		}, portHints...),
		Sources: topNKeys(bySrc, 8),
		Targets: topNKeys(byDst, 8),
		Count:   udp,
	}}
}

func detectICMPFlood(packets []models.PacketRow, summary models.Summary) []models.Threat {
	icmp := 0
	bySrc := map[string]int{}
	byDst := map[string]int{}
	echo := 0

	for _, p := range packets {
		up := strings.ToUpper(p.Protocol)
		if !strings.Contains(up, "ICMP") {
			continue
		}
		icmp++
		bySrc[p.SrcIP]++
		byDst[p.DstIP]++
		if p.ICMPType == 8 || p.ICMPType == 0 {
			echo++
		}
	}

	if icmp < 100 {
		return nil
	}
	share := float64(icmp) / float64(summary.PacketCount)
	if share < 0.4 && icmp < 500 {
		return nil
	}

	sev := models.SeverityMedium
	conf := 0.7
	if icmp >= 500 || share >= 0.6 {
		sev = models.SeverityHigh
		conf = 0.85
	}

	return []models.Threat{{
		ID:       "ddos-icmp-flood",
		Category: "ddos",
		Title:    "Возможный ICMP flood",
		Description: fmt.Sprintf(
			"%d ICMP-пакетов (echo≈%d). Массовый ICMP echo — признак ping flood.",
			icmp, echo,
		),
		Severity:   sev,
		Confidence: conf,
		Indicators: []string{
			fmt.Sprintf("icmp_packets=%d", icmp),
			fmt.Sprintf("echo_related=%d", echo),
			fmt.Sprintf("share=%.0f%%", share*100),
		},
		Sources: topNKeys(bySrc, 8),
		Targets: topNKeys(byDst, 8),
		Count:   icmp,
	}}
}

func detectHighPPS(summary models.Summary) []models.Threat {
	if summary.DurationSec < 0.5 || summary.PPS < 1000 {
		return nil
	}
	sev := models.SeverityMedium
	conf := 0.55
	if summary.PPS >= 5000 {
		sev = models.SeverityHigh
		conf = 0.75
	}
	if summary.PPS >= 20000 {
		sev = models.SeverityCritical
		conf = 0.9
	}
	return []models.Threat{{
		ID:       "ddos-high-pps",
		Category: "ddos",
		Title:    "Аномально высокий PPS",
		Description: fmt.Sprintf(
			"Средняя скорость ≈ %.0f пакетов/с за %.2f с. Может указывать на flood или amplification-атаку.",
			summary.PPS, summary.DurationSec,
		),
		Severity:   sev,
		Confidence: conf,
		Indicators: []string{fmt.Sprintf("pps=%.0f", summary.PPS)},
	}}
}

func topNKeys(m map[string]int, n int) []string {
	return keysFromTop(m, n)
}

func keysFromTop(m map[string]int, n int) []string {
	list := topKeys(m, n)
	out := make([]string, 0, len(list))
	for _, s := range list {
		// "ip (count)" -> ip
		if i := strings.Index(s, " ("); i > 0 {
			out = append(out, s[:i])
		} else {
			out = append(out, s)
		}
	}
	return out
}
