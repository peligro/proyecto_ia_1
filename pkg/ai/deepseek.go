package ai

import "context"

type DeepSeekProvider struct{ *openAICompatibleProvider }

func newDeepSeekProvider(cfg *Config) (*DeepSeekProvider, error) {
	base, err := newOpenAICompatibleProvider(cfg, ProviderDeepSeek)  // ← Pasar provider
	if err != nil {
		return nil, err
	}
	return &DeepSeekProvider{base}, nil
}

func (d *DeepSeekProvider) ChatCompletion(ctx context.Context, prompt string, opts ...Option) (string, error) {
	return d.openAICompatibleProvider.ChatCompletion(ctx, prompt, opts...)
}
func (d *DeepSeekProvider) EstimateCost(prompt string) (int, float64) {
	return d.openAICompatibleProvider.EstimateCost(prompt)
}
func (d *DeepSeekProvider) Provider() Provider { return ProviderDeepSeek }