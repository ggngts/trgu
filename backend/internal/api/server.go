package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"sharaga/internal/config"
	"sharaga/internal/detect"
	"sharaga/internal/gemini"
	"sharaga/internal/models"
	"sharaga/internal/store"
	"sharaga/internal/tshark"
)

type Server struct {
	cfg         config.Config
	tshark      *tshark.Runner
	store       *store.Memory
	gemini      *gemini.Client
	mux         *http.ServeMux
	liveMu      sync.RWMutex
	livePackets []models.PacketRow
	liveLogs    []string
	liveStatus  string
}

func New(cfg config.Config, ts *tshark.Runner, st *store.Memory, gm *gemini.Client) *Server {
	s := &Server{cfg: cfg, tshark: ts, store: st, gemini: gm, mux: http.NewServeMux()}
	s.liveStatus = "Ожидание tshark"
	go ts.Capture(context.Background(), cfg.CaptureInterface, s.addLivePacket, s.addLiveLog)
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.withCORS(s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/live", s.handleLive)
	s.mux.HandleFunc("POST /api/analyze", s.handleAnalyze)
	s.mux.HandleFunc("GET /api/analysis/{id}", s.handleGetAnalysis)
	s.mux.HandleFunc("POST /api/analysis/{id}/ai", s.handleAI)

	if s.cfg.StaticDir != "" {
		fs := http.FileServer(http.Dir(s.cfg.StaticDir))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			path := filepath.Join(s.cfg.StaticDir, filepath.Clean(r.URL.Path))
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				fs.ServeHTTP(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(s.cfg.StaticDir, "index.html"))
		})
	}
}

func (s *Server) addLivePacket(p models.PacketRow) {
	s.liveMu.Lock()
	s.livePackets = append(s.livePackets, p)
	if len(s.livePackets) > 20000 {
		s.livePackets = append([]models.PacketRow(nil), s.livePackets[len(s.livePackets)-20000:]...)
	}
	s.liveStatus = "Захват активен"
	s.liveMu.Unlock()
}

func (s *Server) addLiveLog(msg string) {
	s.liveMu.Lock()
	s.liveStatus = msg
	s.liveLogs = append(s.liveLogs, time.Now().Format("15:04:05")+"  "+msg)
	if len(s.liveLogs) > 100 {
		s.liveLogs = s.liveLogs[len(s.liveLogs)-100:]
	}
	s.liveMu.Unlock()
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		s.liveMu.RLock()
		packets := append([]models.PacketRow{}, s.livePackets...)
		logs := append([]string{}, s.liveLogs...)
		status := s.liveStatus
		s.liveMu.RUnlock()
		summary, protos, talkers, convs := tshark.BuildStats(packets)
		threats, score := detect.Run(packets, summary)
		analysis := models.Analysis{ID: "live", Filename: "Live capture · " + s.cfg.CaptureInterface, CreatedAt: time.Now().UTC(), Summary: summary, Protocols: protos, TopTalkers: talkers, Conversations: convs, Threats: threats, ThreatScore: score}
		payload, _ := json.Marshal(map[string]any{"status": status, "analysis": analysis, "packets": tailPackets(packets, 30), "logs": logs})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

func tailPackets(p []models.PacketRow, n int) []models.PacketRow {
	if len(p) > n {
		p = p[len(p)-n:]
	}
	return p
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	err := s.tshark.Available()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"tshark":       err == nil,
		"tshark_error": errString(err),
		"gemini":       s.gemini.Enabled(),
		"time":         time.Now().UTC(),
	})
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if err := s.tshark.Available(); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "tshark недоступен: "+err.Error())
		return
	}

	maxBytes := s.cfg.MaxUploadMB << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+1024)
	if err := r.ParseMultipartForm(maxBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "файл слишком большой или форма некорректна")
		return
	}

	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ожидается multipart field 'file'")
		return
	}
	defer file.Close()

	name := filepath.Base(hdr.Filename)
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		writeErr(w, http.StatusBadRequest, "нужен .pcap / .pcapng / .cap")
		return
	}

	if err := os.MkdirAll(s.cfg.UploadDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "не удалось создать upload dir")
		return
	}

	id := uuid.NewString()
	dstPath := filepath.Join(s.cfg.UploadDir, id+ext)
	dst, err := os.Create(dstPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "не удалось сохранить файл")
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		os.Remove(dstPath)
		writeErr(w, http.StatusInternalServerError, "ошибка записи файла")
		return
	}
	dst.Close()
	defer os.Remove(dstPath)

	packets, err := s.tshark.ParsePackets(dstPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "tshark не смог разобрать файл: "+err.Error())
		return
	}

	summary, protocols, talkers, convs := tshark.BuildStats(packets)
	threats, score := detect.Run(packets, summary)

	analysis := &models.Analysis{
		ID:            id,
		Filename:      name,
		CreatedAt:     time.Now().UTC(),
		Summary:       summary,
		Protocols:     protocols,
		TopTalkers:    talkers,
		Conversations: convs,
		Threats:       threats,
		ThreatScore:   score,
	}

	// Keep packets only if AI might need richer context later — store trims by TTL.
	// Cap stored packets to avoid RAM blowups on huge captures.
	stored := packets
	if len(stored) > 50000 {
		stored = stored[:50000]
	}
	s.store.Put(analysis, stored)

	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.store.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "анализ не найден или истёк")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleAI(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var a *models.Analysis
	if id == "live" {
		s.liveMu.RLock()
		packets := append([]models.PacketRow(nil), s.livePackets...)
		s.liveMu.RUnlock()
		summary, protocols, talkers, convs := tshark.BuildStats(packets)
		threats, score := detect.Run(packets, summary)
		a = &models.Analysis{ID: "live", Filename: "Live capture", CreatedAt: time.Now().UTC(), Summary: summary, Protocols: protocols, TopTalkers: talkers, Conversations: convs, Threats: threats, ThreatScore: score}
	} else {
		var ok bool
		a, _, ok = s.store.GetWithPackets(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "анализ не найден или истёк")
			return
		}
	}
	if !s.gemini.Enabled() {
		writeErr(w, http.StatusServiceUnavailable, "GEMINI_API_KEY не настроен")
		return
	}

	var req models.AIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "некорректный JSON")
		return
	}

	ctx := r.Context()
	resp, err := s.gemini.Analyze(ctx, a, req.Question)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

var allowedOrigins = map[string]struct{}{
	"https://tg.mpnetwork.space": {},
	"http://tg.mpnetwork.space":  {},
	"http://localhost:5173":      {},
	"http://127.0.0.1:5173":      {},
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		} else if origin == "" {
			// same-origin / curl
		} else if strings.HasSuffix(origin, ".mpnetwork.space") || strings.Contains(origin, "localhost") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
