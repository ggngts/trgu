package tshark

import (
	"sort"
	"strings"

	"sharaga/internal/models"
)

func BuildStats(packets []models.PacketRow) (models.Summary, []models.ProtocolStat, []models.Talker, []models.Conversation) {
	summary := models.Summary{PacketCount: len(packets)}
	if len(packets) == 0 {
		return summary, nil, nil, nil
	}

	protoPkts := map[string]int{}
	protoBytes := map[string]int64{}
	ipPkts := map[string]int{}
	ipBytes := map[string]int64{}
	ipSent := map[string]int64{}
	ipRecv := map[string]int64{}
	ips := map[string]struct{}{}
	ports := map[int]struct{}{}

	type convKey struct{ a, b, proto string }
	type convAgg struct {
		packets int
		bytes   int64
		t0, t1  float64
	}
	convs := map[convKey]*convAgg{}

	var maxT float64
	for _, p := range packets {
		summary.BytesTotal += int64(p.Length)
		if p.TimeRel > maxT {
			maxT = p.TimeRel
		}

		proto := normalizeProto(p.Protocol)
		protoPkts[proto]++
		protoBytes[proto] += int64(p.Length)

		if isTCP(p) {
			summary.TCPCount++
		} else if isUDP(p) {
			summary.UDPCount++
		}
		if strings.EqualFold(p.Protocol, "ICMP") || strings.Contains(strings.ToUpper(p.Protocol), "ICMP") {
			summary.ICMPCount++
		}
		if p.DNSQuery != "" || strings.EqualFold(p.Protocol, "DNS") {
			summary.DNSCount++
		}
		if p.HTTPMethod != "" || strings.Contains(strings.ToUpper(p.Protocol), "HTTP") {
			summary.HTTPCount++
		}
		if p.TLSServerName != "" || strings.Contains(strings.ToUpper(p.Protocol), "TLS") || strings.Contains(strings.ToUpper(p.Protocol), "SSL") {
			summary.TLSCount++
		}

		if p.SrcIP != "" {
			ips[p.SrcIP] = struct{}{}
			ipPkts[p.SrcIP]++
			ipBytes[p.SrcIP] += int64(p.Length)
			ipSent[p.SrcIP] += int64(p.Length)
		}
		if p.DstIP != "" {
			ips[p.DstIP] = struct{}{}
			ipPkts[p.DstIP]++
			ipBytes[p.DstIP] += int64(p.Length)
			ipRecv[p.DstIP] += int64(p.Length)
		}
		if p.SrcPort > 0 {
			ports[p.SrcPort] = struct{}{}
		}
		if p.DstPort > 0 {
			ports[p.DstPort] = struct{}{}
		}

		if p.SrcIP != "" && p.DstIP != "" {
			a, b := p.SrcIP, p.DstIP
			if a > b {
				a, b = b, a
			}
			k := convKey{a, b, proto}
			c, ok := convs[k]
			if !ok {
				c = &convAgg{t0: p.TimeRel, t1: p.TimeRel}
				convs[k] = c
			}
			c.packets++
			c.bytes += int64(p.Length)
			if p.TimeRel < c.t0 {
				c.t0 = p.TimeRel
			}
			if p.TimeRel > c.t1 {
				c.t1 = p.TimeRel
			}
		}
	}

	summary.DurationSec = maxT
	summary.UniqueIPs = len(ips)
	summary.UniquePorts = len(ports)
	if summary.PacketCount > 0 {
		summary.AvgPacketSize = float64(summary.BytesTotal) / float64(summary.PacketCount)
	}
	if maxT > 0 {
		summary.PPS = float64(summary.PacketCount) / maxT
	}

	protocols := make([]models.ProtocolStat, 0, len(protoPkts))
	for name, pkts := range protoPkts {
		pct := 0.0
		if summary.PacketCount > 0 {
			pct = float64(pkts) / float64(summary.PacketCount) * 100
		}
		protocols = append(protocols, models.ProtocolStat{
			Name: name, Packets: pkts, Bytes: protoBytes[name], Percentage: pct,
		})
	}
	sort.Slice(protocols, func(i, j int) bool { return protocols[i].Packets > protocols[j].Packets })
	if len(protocols) > 20 {
		protocols = protocols[:20]
	}

	talkers := make([]models.Talker, 0, len(ipPkts))
	for ip, pkts := range ipPkts {
		talkers = append(talkers, models.Talker{
			IP: ip, Packets: pkts, Bytes: ipBytes[ip], Sent: ipSent[ip], Recv: ipRecv[ip],
		})
	}
	sort.Slice(talkers, func(i, j int) bool { return talkers[i].Bytes > talkers[j].Bytes })
	if len(talkers) > 25 {
		talkers = talkers[:25]
	}

	conversations := make([]models.Conversation, 0, len(convs))
	for k, c := range convs {
		conversations = append(conversations, models.Conversation{
			Src: k.a, Dst: k.b, Protocol: k.proto,
			Packets: c.packets, Bytes: c.bytes, Duration: c.t1 - c.t0,
		})
	}
	sort.Slice(conversations, func(i, j int) bool { return conversations[i].Bytes > conversations[j].Bytes })
	if len(conversations) > 40 {
		conversations = conversations[:40]
	}

	return summary, protocols, talkers, conversations
}

func normalizeProto(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "UNKNOWN"
	}
	up := strings.ToUpper(p)
	switch {
	case strings.Contains(up, "TLS"), strings.Contains(up, "SSL"):
		return "TLS"
	case strings.Contains(up, "HTTP"):
		return "HTTP"
	case up == "DNS":
		return "DNS"
	case strings.Contains(up, "ICMP"):
		return "ICMP"
	case up == "TCP":
		return "TCP"
	case up == "UDP":
		return "UDP"
	case strings.Contains(up, "QUIC"):
		return "QUIC"
	case strings.Contains(up, "SSH"):
		return "SSH"
	case strings.Contains(up, "ARP"):
		return "ARP"
	default:
		return p
	}
}

func isTCP(p models.PacketRow) bool {
	up := strings.ToUpper(p.Protocol)
	return strings.Contains(up, "TCP") || p.TCPSyn || p.TCPAck || p.TCPFin || p.TCPRst
}

func isUDP(p models.PacketRow) bool {
	up := strings.ToUpper(p.Protocol)
	return up == "UDP" || strings.Contains(up, "DNS") || strings.Contains(up, "QUIC") ||
		(p.SrcPort > 0 && !isTCP(p) && !strings.Contains(up, "ICMP") && p.Protocol != "")
}
