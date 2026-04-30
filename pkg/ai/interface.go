package ai

import "context"

// AIProvider define el interface que todos los providers deben implementar
type AIProvider interface {
	// ChatCompletion envía un prompt y devuelve la respuesta de la IA
	ChatCompletion(ctx context.Context, prompt string, opts ...Option) (string, error)
	
	// EstimateCost estima tokens usados y costo en USD
	EstimateCost(prompt string) (tokens int, costUSD float64)
	
	// Provider devuelve el identificador del provider
	Provider() Provider
}

// Provider enum de providers soportados
type Provider string

const (
	ProviderGemini   Provider = "gemini"
	ProviderMistral  Provider = "mistral"
	ProviderDeepSeek Provider = "deepseek"
	ProviderOpenAI   Provider = "openai"
	ProviderClaude   Provider = "claude"
	ProviderGroq     Provider = "groq"
)
