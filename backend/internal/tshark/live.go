package tshark

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"sharaga/internal/models"
)

// Capture continuously reads tshark's line-buffered field output and restarts it after failures.
func (r *Runner) Capture(ctx context.Context, iface, pipe string, packet func(models.PacketRow), status func(string)) {
	if iface == "" {
		iface = "any"
	}
	for ctx.Err() == nil {
		var args []string
		captureStatus := "Захват запущен на интерфейсе " + iface
		if pipe = strings.TrimSpace(pipe); pipe != "" {
			args = append([]string{"-l", "-n", "-r", pipe}, fieldArgs()...)
			captureStatus = "Обрабатываю live-поток с сетевого пространства хоста"
		} else {
			args = append([]string{"-l", "-n", "-p", "-i", iface}, fieldArgs()...)
		}
		cmd := exec.CommandContext(ctx, r.Path, args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			status("tshark stdout: " + err.Error())
			return
		}
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			status("tshark запуск: " + err.Error())
		} else {
			status(captureStatus)
			go func() {
				s := bufio.NewScanner(stderr)
				for s.Scan() {
					if msg := strings.TrimSpace(s.Text()); msg != "" {
						status(msg)
					}
				}
			}()
			s := bufio.NewScanner(stdout)
			s.Buffer(make([]byte, 64*1024), 1024*1024)
			for s.Scan() {
				if row, ok := parseRow(s.Text()); ok {
					packet(row)
				}
			}
			if err := s.Err(); err != nil {
				status("Чтение tshark: " + err.Error())
			}
			if err := cmd.Wait(); err != nil && ctx.Err() == nil {
				status("tshark остановился: " + err.Error())
			}
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		status(fmt.Sprintf("Перезапуск tshark (%s)", iface))
	}
}
