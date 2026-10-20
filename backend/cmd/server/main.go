package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"sharaga/internal/api"
	"sharaga/internal/config"
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
	srv := api.New(cfg, ts, st)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		// Live SSE streams stay open and send updates continuously.
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("traffic-guardian listening on %s", cfg.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
