package ai

import "context"

type OpenAIProvider struct{ *openAICompatibleProvider }

func newOpenAIProvider(cfg *Config) (*OpenAIProvider, error) {
	base, err := newOpenAICompatibleProvider(cfg, ProviderOpenAI)  // ← Pasar provider
	if err != nil {
		return nil, err
	}
	return &OpenAIProvider{base}, nil
}

func (o *OpenAIProvider) ChatCompletion(ctx context.Context, prompt string, opts ...Option) (string, error) {
	return o.openAICompatibleProvider.ChatCompletion(ctx, prompt, opts...)
}
func (o *OpenAIProvider) EstimateCost(prompt string) (int, float64) {
	return o.openAICompatibleProvider.EstimateCost(prompt)
}
func (o *OpenAIProvider) Provider() Provider { return ProviderOpenAI }