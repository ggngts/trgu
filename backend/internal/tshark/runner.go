package tshark

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"sharaga/internal/models"
)

type Runner struct {
	Path string
}

func New(path string) *Runner {
	if path == "" {
		path = "tshark"
	}
	return &Runner{Path: path}
}

func (r *Runner) Available() error {
	cmd := exec.Command(r.Path, "-v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tshark not available: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ParsePackets exports a compact field set for heuristic analysis.
func (r *Runner) ParsePackets(pcapPath string) ([]models.PacketRow, error) {
	args := append([]string{"-r", pcapPath}, fieldArgs()...)

	cmd := exec.Command(r.Path, args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("tshark parse failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}

	rows := make([]models.PacketRow, 0, 1024)
	sc := bufio.NewScanner(bytes.NewReader(out))
	buf := make([]byte, 0, 1024*64)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		if row, ok := parseRow(sc.Text()); ok {
			rows = append(rows, row)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func fieldArgs() []string {
	return []string{
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "quote=n",
		"-E", "occurrence=f",
		"-e", "frame.number",
		"-e", "frame.time_relative",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "udp.srcport",
		"-e", "udp.dstport",
		"-e", "_ws.col.Protocol",
		"-e", "frame.len",
		"-e", "tcp.flags.syn",
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.fin",
		"-e", "tcp.flags.reset",
		"-e", "icmp.type",
		"-e", "dns.qry.name",
		"-e", "http.host",
		"-e", "http.request.uri",
		"-e", "http.request.method",
		"-e", "tls.handshake.extensions_server_name",
	}
}

func parseRow(line string) (models.PacketRow, bool) {
	if line == "" {
		return models.PacketRow{}, false
	}
	cols := strings.Split(line, "\t")
	for len(cols) < 20 {
		cols = append(cols, "")
	}

	row := models.PacketRow{
		Number:        atoi(cols[0]),
		TimeRel:       atof(cols[1]),
		SrcIP:         cols[2],
		DstIP:         cols[3],
		Protocol:      cols[8],
		Length:        atoi(cols[9]),
		TCPSyn:        cols[10] == "1" || cols[10] == "True",
		TCPAck:        cols[11] == "1" || cols[11] == "True",
		TCPFin:        cols[12] == "1" || cols[12] == "True",
		TCPRst:        cols[13] == "1" || cols[13] == "True",
		ICMPType:      atoi(cols[14]),
		DNSQuery:      cols[15],
		HTTPHost:      cols[16],
		HTTPURI:       cols[17],
		HTTPMethod:    cols[18],
		TLSServerName: cols[19],
	}

	tcpSport, tcpDport := atoi(cols[4]), atoi(cols[5])
	udpSport, udpDport := atoi(cols[6]), atoi(cols[7])
	if tcpSport > 0 || tcpDport > 0 {
		row.SrcPort, row.DstPort = tcpSport, tcpDport
	} else {
		row.SrcPort, row.DstPort = udpSport, udpDport
	}

	return row, true
}

func (r *Runner) ProtocolHierarchy(pcapPath string) (string, error) {
	return r.stat(pcapPath, "io,phs")
}

func (r *Runner) IPConversations(pcapPath string) (string, error) {
	return r.stat(pcapPath, "conv,ip")
}

func (r *Runner) Endpoints(pcapPath string) (string, error) {
	return r.stat(pcapPath, "endpoints,ip")
}

func (r *Runner) stat(pcapPath, z string) (string, error) {
	cmd := exec.Command(r.Path, "-r", pcapPath, "-q", "-z", z)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tshark -z %s: %w (%s)", z, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func atoi(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// take first value if multi-occurrence leaked
	if i := strings.IndexAny(s, ","); i >= 0 {
		s = s[:i]
	}
	n, _ := strconv.Atoi(s)
	return n
}

func atof(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, _ := strconv.ParseFloat(s, 64)
	return n
}
