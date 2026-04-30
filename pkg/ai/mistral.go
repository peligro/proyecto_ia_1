package ai

import "context"

type MistralProvider struct{ *openAICompatibleProvider }

func newMistralProvider(cfg *Config) (*MistralProvider, error) {
	base, err := newOpenAICompatibleProvider(cfg, ProviderMistral)  // ← Pasar provider
	if err != nil {
		return nil, err
	}
	return &MistralProvider{base}, nil
}

func (m *MistralProvider) ChatCompletion(ctx context.Context, prompt string, opts ...Option) (string, error) {
	return m.openAICompatibleProvider.ChatCompletion(ctx, prompt, opts...)
}
func (m *MistralProvider) EstimateCost(prompt string) (int, float64) {
	return m.openAICompatibleProvider.EstimateCost(prompt)
}
func (m *MistralProvider) Provider() Provider { return ProviderMistral }