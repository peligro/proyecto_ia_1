package ai

import (
	"context"
	"fmt"
)

// ClaudeProvider stub para Claude (API propia, no OpenAI-compatible)
type ClaudeProvider struct{ cfg *Config }

func newClaudeProvider(cfg *Config) (*ClaudeProvider, error) {
	return &ClaudeProvider{cfg: cfg}, nil
}

func (c *ClaudeProvider) ChatCompletion(ctx context.Context, prompt string, opts ...Option) (string, error) {
	return "", fmt.Errorf("Claude provider not implemented yet. Use gemini, mistral, deepseek, or openai")
}
func (c *ClaudeProvider) EstimateCost(prompt string) (int, float64) { return 0, 0 }
func (c *ClaudeProvider) Provider() Provider { return ProviderClaude }