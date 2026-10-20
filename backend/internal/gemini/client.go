package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sharaga/internal/models"
)

type Client struct {
	APIKey string
	Model  string
	HTTP   *http.Client
}

func New(apiKey, model string) *Client {
	if model == "" {
		model = "gemini-2.0-flash"
	}
	return &Client{
		APIKey: apiKey,
		Model:  model,
		HTTP:   &http.Client{Timeout: 90 * time.Second},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && strings.TrimSpace(c.APIKey) != ""
}

type generateRequest struct {
	Contents []content `json:"contents"`
}

type content struct {
	Parts []part `json:"parts"`
}

type part struct {
	Text string `json:"text"`
}

type generateResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

func (c *Client) Analyze(ctx context.Context, analysis *models.Analysis, question string) (*models.AIResponse, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("GEMINI_API_KEY не задан")
	}

	prompt := buildPrompt(analysis, question)
	body, _ := json.Marshal(generateRequest{
		Contents: []content{{Parts: []part{{Text: prompt}}}},
	})

	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		c.Model, c.APIKey,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var parsed generateResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("gemini decode: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("gemini: %s (%s)", parsed.Error.Message, parsed.Error.Status)
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("gemini HTTP %d: %s", res.StatusCode, string(raw))
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini: пустой ответ")
	}

	var b strings.Builder
	for _, p := range parsed.Candidates[0].Content.Parts {
		b.WriteString(p.Text)
	}

	return &models.AIResponse{
		Answer:    b.String(),
		Model:     c.Model,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func buildPrompt(a *models.Analysis, question string) string {
	var sb strings.Builder
	sb.WriteString("Ты — аналитик сетевого трафика. Отвечай по-русски, конкретно, без воды.\n")
	sb.WriteString("Ниже сводка PCAP-анализа и локальные эвристики угроз. Сделай экспертный разбор.\n\n")

	sb.WriteString(fmt.Sprintf("Файл: %s\n", a.Filename))
	sb.WriteString(fmt.Sprintf("Пакетов: %d | Байт: %d | Длительность: %.2fs | PPS: %.1f\n",
		a.Summary.PacketCount, a.Summary.BytesTotal, a.Summary.DurationSec, a.Summary.PPS))
	sb.WriteString(fmt.Sprintf("TCP/UDP/ICMP/DNS/HTTP/TLS: %d/%d/%d/%d/%d/%d\n",
		a.Summary.TCPCount, a.Summary.UDPCount, a.Summary.ICMPCount,
		a.Summary.DNSCount, a.Summary.HTTPCount, a.Summary.TLSCount))
	sb.WriteString(fmt.Sprintf("Уникальных IP: %d | Портов: %d | Threat score: %d/100\n\n",
		a.Summary.UniqueIPs, a.Summary.UniquePorts, a.ThreatScore))

	sb.WriteString("Протоколы (топ):\n")
	for i, p := range a.Protocols {
		if i >= 12 {
			break
		}
		sb.WriteString(fmt.Sprintf("- %s: %d pkt (%.1f%%)\n", p.Name, p.Packets, p.Percentage))
	}

	sb.WriteString("\nTop talkers:\n")
	for i, t := range a.TopTalkers {
		if i >= 12 {
			break
		}
		sb.WriteString(fmt.Sprintf("- %s: %d pkt, %d bytes\n", t.IP, t.Packets, t.Bytes))
	}

	sb.WriteString("\nЛокальные детекции:\n")
	if len(a.Threats) == 0 {
		sb.WriteString("- угроз не найдено эвристиками\n")
	}
	for _, t := range a.Threats {
		sb.WriteString(fmt.Sprintf("- [%s/%s] %s — %s (conf=%.2f)\n",
			t.Severity, t.Category, t.Title, t.Description, t.Confidence))
	}

	sb.WriteString("\nВопрос пользователя:\n")
	if strings.TrimSpace(question) == "" {
		sb.WriteString("Дай общий вердикт: что происходит в трафике, какие риски, что проверить дальше.")
	} else {
		sb.WriteString(question)
	}
	return sb.String()
}
