package models

import "time"

type Analysis struct {
	ID            string         `json:"id"`
	Filename      string         `json:"filename"`
	CreatedAt     time.Time      `json:"created_at"`
	Summary       Summary        `json:"summary"`
	Protocols     []ProtocolStat `json:"protocols"`
	TopTalkers    []Talker       `json:"top_talkers"`
	Conversations []Conversation `json:"conversations"`
	Threats       []Threat       `json:"threats"`
	ThreatScore   int            `json:"threat_score"` // 0-100
}

type Summary struct {
	PacketCount   int     `json:"packet_count"`
	BytesTotal    int64   `json:"bytes_total"`
	DurationSec   float64 `json:"duration_sec"`
	AvgPacketSize float64 `json:"avg_packet_size"`
	PPS           float64 `json:"pps"`
	UniqueIPs     int     `json:"unique_ips"`
	UniquePorts   int     `json:"unique_ports"`
	TCPCount      int     `json:"tcp_count"`
	UDPCount      int     `json:"udp_count"`
	ICMPCount     int     `json:"icmp_count"`
	DNSCount      int     `json:"dns_count"`
	HTTPCount     int     `json:"http_count"`
	TLSCount      int     `json:"tls_count"`
}

type ProtocolStat struct {
	Name       string  `json:"name"`
	Packets    int     `json:"packets"`
	Bytes      int64   `json:"bytes"`
	Percentage float64 `json:"percentage"`
}

type Talker struct {
	IP      string `json:"ip"`
	Packets int    `json:"packets"`
	Bytes   int64  `json:"bytes"`
	Sent    int64  `json:"sent"`
	Recv    int64  `json:"recv"`
}

type Conversation struct {
	Src      string  `json:"src"`
	Dst      string  `json:"dst"`
	Protocol string  `json:"protocol"`
	Packets  int     `json:"packets"`
	Bytes    int64   `json:"bytes"`
	Duration float64 `json:"duration"`
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Threat struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"` // ddos, scan, malware, anomaly
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Confidence  float64  `json:"confidence"` // 0-1
	Indicators  []string `json:"indicators"`
	Sources     []string `json:"sources,omitempty"`
	Targets     []string `json:"targets,omitempty"`
	Count       int      `json:"count,omitempty"`
}

// PacketRow is a normalized tshark field export row used by detectors.
type PacketRow struct {
	Number        int
	TimeRel       float64
	SrcIP         string
	DstIP         string
	SrcPort       int
	DstPort       int
	Protocol      string
	Length        int
	TCPFlags      string
	TCPSyn        bool
	TCPAck        bool
	TCPFin        bool
	TCPRst        bool
	ICMPType      int
	DNSQuery      string
	HTTPHost      string
	HTTPURI       string
	HTTPMethod    string
	TLSServerName string
}
