package config

import (
	"os"
	"time"
)

// Defaults are baked into the binary — no .env files.
const (
	ListenAddr       = ":5444"
	MaxUploadMB      = 200
	AnalysisTTLMin   = 60
	UploadDir        = "/tmp/traffic-guardian"
	TsharkPath       = "tshark"
	StaticDir        = ""
	CaptureInterface = "any"
)

type Config struct {
	Addr             string
	MaxUploadMB      int64
	UploadDir        string
	AnalysisTTL      time.Duration
	TsharkPath       string
	StaticDir        string
	CaptureInterface string
	CapturePipe      string
}

func Load() Config {
	return Config{
		Addr:             ListenAddr,
		MaxUploadMB:      MaxUploadMB,
		UploadDir:        UploadDir,
		AnalysisTTL:      time.Duration(AnalysisTTLMin) * time.Minute,
		TsharkPath:       TsharkPath,
		StaticDir:        StaticDir,
		CaptureInterface: envOr("CAPTURE_INTERFACE", CaptureInterface),
		CapturePipe:      os.Getenv("CAPTURE_PIPE"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
