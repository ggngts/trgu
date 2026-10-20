package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"sharaga/internal/api"
	"sharaga/internal/config"
	"sharaga/internal/gemini"
	"sharaga/internal/store"
	"sharaga/internal/tshark"
)

func main() {
	cfg := config.Load()
	if err := os.MkdirAll(cfg.UploadDir, 0o755); err != nil {
		log.Fatalf("upload dir: %v", err)
	}

	ts := tshark.New(cfg.TsharkPath)
	if err := ts.Available(); err != nil {
		log.Printf("warning: tshark not available yet: %v", err)
	}

	st := store.New(cfg.AnalysisTTL)
	gm := gemini.New(cfg.GeminiAPIKey, cfg.GeminiModel)
	srv := api.New(cfg, ts, st, gm)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		// Live SSE streams stay open and send updates continuously.
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("traffic-guardian listening on %s (gemini=%v)", cfg.Addr, gm.Enabled())
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
