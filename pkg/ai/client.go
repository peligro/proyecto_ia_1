package ai

import "fmt"

// NewProvider factory: crea el provider correcto según config
func NewProvider(cfg *Config) (AIProvider, error) {
	switch cfg.Provider {
	case ProviderGemini:
		return newGeminiProvider(cfg)
	case ProviderMistral:
		return newMistralProvider(cfg)
	case ProviderDeepSeek:
		return newDeepSeekProvider(cfg)
	case ProviderOpenAI:
		return newOpenAIProvider(cfg)
	case ProviderClaude:
		return newClaudeProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}
}