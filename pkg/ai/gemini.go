package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GeminiProvider implementa AIProvider para Google Gemini (API v1beta nuevo formato)
type GeminiProvider struct {
	apiKey  string
	baseURL string
	model   string
	client  *http.Client
}

// GeminiRequest estructura de request para Gemini API (nuevo formato)
type GeminiRequest struct {
	Contents         []GeminiContent  `json:"contents"`
	GenerationConfig GenerationConfig `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`  // "user" o "model"
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GenerationConfig struct {
	Temperature     float32 `json:"temperature,omitempty"`
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
	TopP            float32 `json:"topP,omitempty"`
	TopK            int     `json:"topK,omitempty"`
}

type GeminiResponse struct {
	Candidates     []GeminiCandidate     `json:"candidates"`
	PromptFeedback *GeminiPromptFeedback `json:"promptFeedback,omitempty"`
}

type GeminiCandidate struct {
	Content      GeminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
}

type GeminiPromptFeedback struct {
	BlockReason string `json:"blockReason,omitempty"`
}

// newGeminiProvider crea una nueva instancia del provider Gemini
func newGeminiProvider(cfg *Config) (*GeminiProvider, error) {
	return &GeminiProvider{
		apiKey:  cfg.APIKey,
		baseURL: strings.TrimSuffix(cfg.BaseURL, "/"),
		model:   cfg.Model,
		client: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
	}, nil
}

// ChatCompletion envía un prompt a Gemini y devuelve la respuesta (formato nuevo con header)
func (g *GeminiProvider) ChatCompletion(ctx context.Context, prompt string, opts ...Option) (string, error) {
	// Procesar opciones
	options := &requestOptions{
		Temperature: 0.3,
		MaxTokens:   1000,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Construir request (formato nuevo con role:"user")
	reqBody := GeminiRequest{
		Contents: []GeminiContent{
			{
				Role: "user",  // ← NUEVO: requerido en formato nuevo
				Parts: []GeminiPart{
					{Text: prompt},
				},
			},
		},
		GenerationConfig: GenerationConfig{
			Temperature:     options.Temperature,
			MaxOutputTokens: options.MaxTokens,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// URL sin API key como query param (formato nuevo)
	url := fmt.Sprintf("%s/models/%s:generateContent", g.baseURL, g.model)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Headers del formato nuevo
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", g.apiKey)  // ← CLAVE: header en lugar de query param

	// Ejecutar request
	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Gemini API error (%d): %s", resp.StatusCode, string(body))
	}

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Verificar bloqueos de seguridad
	if geminiResp.PromptFeedback != nil && geminiResp.PromptFeedback.BlockReason != "" {
		return "", fmt.Errorf("content blocked by Gemini: %s", geminiResp.PromptFeedback.BlockReason)
	}

	// Extraer respuesta
	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no content in Gemini response")
	}

	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

// EstimateCost estima tokens y costo para Gemini
func (g *GeminiProvider) EstimateCost(prompt string) (tokens int, costUSD float64) {
	// Aproximación: 1 token ≈ 4 caracteres
	tokens = len(prompt) / 4
	
	// Costo aproximado para Gemini Flash: ~$0.000125 / 1K tokens input
	costPer1K := 0.000125
	costUSD = float64(tokens) / 1000 * costPer1K
	
	return tokens, costUSD
}

// Provider devuelve el nombre del provider
func (g *GeminiProvider) Provider() Provider {
	return ProviderGemini
}