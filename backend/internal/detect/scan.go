package detect

import (
	"fmt"

	"sharaga/internal/models"
)

func detectPortScan(packets []models.PacketRow) []models.Threat {
	// vertical scan: one src -> one dst, many distinct dst ports, few packets each
	type pair struct{ src, dst string }
	ports := map[pair]map[int]int{}
	syns := map[pair]int{}

	for _, p := range packets {
		if p.SrcIP == "" || p.DstIP == "" || p.DstPort == 0 {
			continue
		}
		if !p.TCPSyn && !isLikelyUDPProbe(p) {
			continue
		}
		k := pair{p.SrcIP, p.DstIP}
		if ports[k] == nil {
			ports[k] = map[int]int{}
		}
		ports[k][p.DstPort]++
		if p.TCPSyn && !p.TCPAck {
			syns[k]++
		}
	}

	var threats []models.Threat
	for k, portMap := range ports {
		if len(portMap) < 20 {
			continue
		}
		singleHit := 0
		for _, c := range portMap {
			if c <= 2 {
				singleHit++
			}
		}
		if float64(singleHit)/float64(len(portMap)) < 0.7 {
			continue
		}

		sev := models.SeverityMedium
		conf := 0.7
		if len(portMap) >= 50 {
			sev = models.SeverityHigh
			conf = 0.85
		}
		if len(portMap) >= 100 {
			sev = models.SeverityCritical
			conf = 0.92
		}

		threats = append(threats, models.Threat{
			ID:       fmt.Sprintf("scan-port-%s-%s", k.src, k.dst),
			Category: "scan",
			Title:    "Вертикальное сканирование портов",
			Description: fmt.Sprintf(
				"%s → %s: %d уникальных портов назначения, из них %d с ≤2 пакетами. Паттерн port scan (nmap-style).",
				k.src, k.dst, len(portMap), singleHit,
			),
			Severity:   sev,
			Confidence: conf,
			Indicators: []string{
				fmt.Sprintf("unique_dst_ports=%d", len(portMap)),
				fmt.Sprintf("sparse_hits=%d", singleHit),
				fmt.Sprintf("syn_probes=%d", syns[k]),
			},
			Sources: []string{k.src},
			Targets: []string{k.dst},
			Count:   len(portMap),
		})
	}
	return threats
}

func detectHostScan(packets []models.PacketRow) []models.Threat {
	// horizontal: one src -> many dst on same few ports
	type key struct {
		src  string
		port int
	}
	dsts := map[key]map[string]struct{}{}

	for _, p := range packets {
		if p.SrcIP == "" || p.DstIP == "" || p.DstPort == 0 {
			continue
		}
		if !(p.TCPSyn && !p.TCPAck) && !isLikelyUDPProbe(p) {
			continue
		}
		k := key{p.SrcIP, p.DstPort}
		if dsts[k] == nil {
			dsts[k] = map[string]struct{}{}
		}
		dsts[k][p.DstIP] = struct{}{}
	}

	var threats []models.Threat
	seenSrc := map[string]int{}
	for k, set := range dsts {
		if len(set) < 30 {
			continue
		}
		seenSrc[k.src] += len(set)
		targets := make([]string, 0, 8)
		i := 0
		for ip := range set {
			if i >= 8 {
				break
			}
			targets = append(targets, ip)
			i++
		}

		sev := models.SeverityMedium
		conf := 0.7
		if len(set) >= 80 {
			sev = models.SeverityHigh
			conf = 0.85
		}

		threats = append(threats, models.Threat{
			ID:       fmt.Sprintf("scan-host-%s-%d", k.src, k.port),
			Category: "scan",
			Title:    "Горизонтальное сканирование хостов",
			Description: fmt.Sprintf(
				"%s прощупывает %d хостов на порту %d. Типичный network sweep / worm-like probe.",
				k.src, len(set), k.port,
			),
			Severity:   sev,
			Confidence: conf,
			Indicators: []string{
				fmt.Sprintf("unique_dst_hosts=%d", len(set)),
				fmt.Sprintf("dst_port=%d", k.port),
			},
			Sources: []string{k.src},
			Targets: targets,
			Count:   len(set),
		})
	}
	return threats
}

func detectNullXmasScan(packets []models.PacketRow) []models.Threat {
	nullLike := 0
	xmasLike := 0
	bySrc := map[string]int{}

	for _, p := range packets {
		// TCP with no SYN/ACK/FIN/RST but has ports — null scan approximation
		// We only export syn/ack/fin/rst bits; null = tcp ports present, all false
		up := p.Protocol
		if p.SrcPort == 0 && p.DstPort == 0 {
			continue
		}
		hasTCPPorts := p.SrcPort > 0 || p.DstPort > 0
		noFlags := !p.TCPSyn && !p.TCPAck && !p.TCPFin && !p.TCPRst
		if !hasTCPPorts || !noFlags {
			continue
		}
		// exclude clear UDP/DNS/QUIC
		if up == "UDP" || up == "DNS" || up == "QUIC" || up == "ICMP" {
			continue
		}
		if up == "TCP" || up == "" {
			nullLike++
			bySrc[p.SrcIP]++
		}
		// XMAS needs FIN+PSH+URG — we don't export PSH/URG; skip precise xmas,
		// use FIN without ACK/SYN as weak signal of crafted scan
		_ = xmasLike
	}

	// Better: FIN scan — FIN set, no ACK/SYN
	finScan := 0
	finSrc := map[string]int{}
	for _, p := range packets {
		if p.TCPFin && !p.TCPAck && !p.TCPSyn {
			finScan++
			finSrc[p.SrcIP]++
		}
	}

	var threats []models.Threat
	if finScan >= 30 {
		sev := models.SeverityMedium
		if finScan >= 100 {
			sev = models.SeverityHigh
		}
		threats = append(threats, models.Threat{
			ID:       "scan-fin",
			Category: "scan",
			Title:    "Возможный FIN/stealth scan",
			Description: fmt.Sprintf(
				"%d FIN-пакетов без SYN/ACK. Используется в stealth-сканировании (nmap -sF).",
				finScan,
			),
			Severity:   sev,
			Confidence: 0.75,
			Indicators: []string{fmt.Sprintf("fin_no_ack=%d", finScan)},
			Sources:    keys(finSrc),
			Count:      finScan,
		})
	}

	if nullLike >= 40 {
		threats = append(threats, models.Threat{
			ID:       "scan-null",
			Category: "scan",
			Title:    "Возможный NULL scan",
			Description: fmt.Sprintf(
				"%d TCP-подобных пакетов без флагов. Паттерн NULL scan (nmap -sN).",
				nullLike,
			),
			Severity:   models.SeverityMedium,
			Confidence: 0.6,
			Indicators: []string{fmt.Sprintf("null_like=%d", nullLike)},
			Sources:    keys(bySrc),
			Count:      nullLike,
		})
	}
	return threats
}

func isLikelyUDPProbe(p models.PacketRow) bool {
	return p.Protocol == "UDP" && p.DstPort > 0 && p.Length > 0 && p.Length < 100
}
