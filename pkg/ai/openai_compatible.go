package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// openAICompatibleProvider base para providers que siguen el formato OpenAI
type openAICompatibleProvider struct {
	apiKey   string
	baseURL  string
	model    string
	provider Provider  // ← NUEVO: para identificar el provider
	client   *http.Client
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float32         `json:"temperature,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

func newOpenAICompatibleProvider(cfg *Config, provider Provider) (*openAICompatibleProvider, error) {
	return &openAICompatibleProvider{
		apiKey:   cfg.APIKey,
		baseURL:  cfg.BaseURL,
		model:    cfg.Model,
		provider: provider,  // ← NUEVO
		client: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
	}, nil
}

func (o *openAICompatibleProvider) ChatCompletion(ctx context.Context, prompt string, opts ...Option) (string, error) {
	options := &requestOptions{Temperature: 0.3, MaxTokens: 1000}
	for _, opt := range opts {
		opt(options)
	}

	reqBody := openAIRequest{
		Model: o.model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: options.Temperature,
		MaxTokens:   options.MaxTokens,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := o.baseURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	var apiResp openAIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return apiResp.Choices[0].Message.Content, nil
}

func (o *openAICompatibleProvider) EstimateCost(prompt string) (tokens int, costUSD float64) {
	tokens = len(prompt) / 4
	// Costo aproximado para modelos pequeños: ~$0.00015 / 1K tokens
	costUSD = float64(tokens) / 1000 * 0.00015
	return tokens, costUSD
}

// Provider devuelve el identificador del provider ← NUEVO
func (o *openAICompatibleProvider) Provider() Provider {
	return o.provider
}