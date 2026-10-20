package config

import (
	"os"
	"time"
)

// Defaults are baked into the binary — no .env files.
const (
	ListenAddr     = ":5444"
	GeminiModel    = "gemini-2.0-flash"
	MaxUploadMB    = 200
	AnalysisTTLMin = 60
	UploadDir      = "/tmp/traffic-guardian"
	TsharkPath     = "tshark"
	StaticDir      = ""
	// GeminiAPIKey: set in Coolify UI as env GEMINI_API_KEY, or paste here.
	GeminiAPIKey = ""
)

type Config struct {
	Addr         string
	GeminiAPIKey string
	GeminiModel  string
	MaxUploadMB  int64
	UploadDir    string
	AnalysisTTL  time.Duration
	TsharkPath   string
	StaticDir    string
}

func Load() Config {
	key := GeminiAPIKey
	if v := os.Getenv("GEMINI_API_KEY"); v != "" {
		key = v
	}

	return Config{
		Addr:         ListenAddr,
		GeminiAPIKey: key,
		GeminiModel:  GeminiModel,
		MaxUploadMB:  MaxUploadMB,
		UploadDir:    UploadDir,
		AnalysisTTL:  time.Duration(AnalysisTTLMin) * time.Minute,
		TsharkPath:   TsharkPath,
		StaticDir:    StaticDir,
	}
}
