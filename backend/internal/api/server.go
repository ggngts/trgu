package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	cfg    config.Config
	tshark *tshark.Runner
	store  *store.Memory
	gemini *gemini.Client
	mux    *http.ServeMux
}

func New(cfg config.Config, ts *tshark.Runner, st *store.Memory, gm *gemini.Client) *Server {
	s := &Server{cfg: cfg, tshark: ts, store: st, gemini: gm, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.withCORS(s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
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
	a, _, ok := s.store.GetWithPackets(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "анализ не найден или истёк")
		return
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
