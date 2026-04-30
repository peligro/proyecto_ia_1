package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Config contiene la configuración para un provider de IA
type Config struct {
	Provider Provider
	APIKey   string
	BaseURL  string
	Model    string
	Timeout  int
}

// GetConfig resuelve la configuración con jerarquía de prioridad
func GetConfig(provider Provider, flagKey, flagModel string) (*Config, error) {
	cfg := &Config{
		Provider: provider,
		Timeout:  30,
	}

	// Cargar .env primero para que las env vars estén disponibles
	_ = godotenv.Load(".env")

	// Helper para leer env vars con fallback
	getEnv := func(keys ...string) string {
		for _, key := range keys {
			if val := os.Getenv(key); val != "" {
				return val
			}
		}
		return ""
	}

	// === API KEY ===
	// 1. Flag --key (máxima prioridad)
	if flagKey != "" {
		cfg.APIKey = flagKey
	}
	// 2. Env var específica: {PROVIDER}_API_KEY
	if cfg.APIKey == "" {
		cfg.APIKey = getEnv(
			strings.ToUpper(string(provider))+"_API_KEY",
		)
	}
	// 3. Env var genérica
	if cfg.APIKey == "" {
		cfg.APIKey = getEnv("AI_API_KEY")
	}
	// 4. Config file ~/.ai-audit/config.yaml
	if cfg.APIKey == "" {
		configPath := filepath.Join(os.Getenv("HOME"), ".ai-audit", "config.yaml")
		if data, err := os.ReadFile(configPath); err == nil {
			var config map[string]map[string]string
			if yaml.Unmarshal(data, &config) == nil {
				if providerCfg, ok := config[string(provider)]; ok {
					if key, ok := providerCfg["api_key"]; ok {
						cfg.APIKey = key
					}
				}
			}
		}
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("no API key found for %s. Use --key or set %s_API_KEY env var", 
			provider, strings.ToUpper(string(provider)))
	}

	// === BASE URL ===
	// 1. Flag --base-url (si lo agregamos en el futuro)
	// 2. Env var: {PROVIDER}_BASE_URL o {PROVIDER}_API_URL (alias para DeepSeek)
	cfg.BaseURL = getEnv(
		strings.ToUpper(string(provider))+"_BASE_URL",
		strings.ToUpper(string(provider))+"_API_URL", // Alias para DeepSeek
	)
	// 3. Config file
	if cfg.BaseURL == "" {
		configPath := filepath.Join(os.Getenv("HOME"), ".ai-audit", "config.yaml")
		if data, err := os.ReadFile(configPath); err == nil {
			var config map[string]map[string]string
			if yaml.Unmarshal(data, &config) == nil {
				if providerCfg, ok := config[string(provider)]; ok {
					if url, ok := providerCfg["base_url"]; ok {
						cfg.BaseURL = url
					}
				}
			}
		}
	}
	// 4. Fallback hardcoded (solo si no hay nada en env/config)
	if cfg.BaseURL == "" {
		cfg.BaseURL = getDefaultBaseURL(provider)
	}

	// === MODEL ===
	// 1. Flag --model
	if flagModel != "" {
		cfg.Model = flagModel
	}
	// 2. Env var: {PROVIDER}_MODEL
	if cfg.Model == "" {
		cfg.Model = getEnv(strings.ToUpper(string(provider)) + "_MODEL")
	}
	// 3. Config file
	if cfg.Model == "" {
		configPath := filepath.Join(os.Getenv("HOME"), ".ai-audit", "config.yaml")
		if data, err := os.ReadFile(configPath); err == nil {
			var config map[string]map[string]string
			if yaml.Unmarshal(data, &config) == nil {
				if providerCfg, ok := config[string(provider)]; ok {
					if model, ok := providerCfg["model"]; ok {
						cfg.Model = model
					}
				}
			}
		}
	}
	// 4. Fallback hardcoded
	if cfg.Model == "" {
		cfg.Model = getDefaultModel(provider)
	}

	return cfg, nil
}

// getDefaultBaseURL devuelve URLs por defecto (solo fallback)
func getDefaultBaseURL(provider Provider) string {
	defaults := map[Provider]string{
		ProviderGemini:   "https://generativelanguage.googleapis.com/v1beta",
		ProviderMistral:  "https://api.mistral.ai/v1",
		ProviderDeepSeek: "https://api.deepseek.com/v1",
		ProviderOpenAI:   "https://api.openai.com/v1",
		ProviderClaude:   "https://api.anthropic.com/v1",
		ProviderGroq:     "https://api.groq.com/openai/v1",
	}
	if url, ok := defaults[provider]; ok {
		return url
	}
	return ""
}

// getDefaultModel devuelve modelos por defecto (solo fallback)
func getDefaultModel(provider Provider) string {
	defaults := map[Provider]string{
		ProviderGemini:   "gemini-2.0-flash",
		ProviderMistral:  "mistral-small-latest",
		ProviderDeepSeek: "deepseek-chat",
		ProviderOpenAI:   "gpt-4o-mini",
		ProviderClaude:   "claude-3-5-sonnet-20241022",
		ProviderGroq:     "llama-3.1-70b-versatile",
	}
	if model, ok := defaults[provider]; ok {
		return model
	}
	return ""
}

// MaskedKey devuelve la key con masking para logs seguros
func (c *Config) MaskedKey() string {
	if len(c.APIKey) < 8 {
		return "***"
	}
	return c.APIKey[:4] + "***" + c.APIKey[len(c.APIKey)-4:]
}