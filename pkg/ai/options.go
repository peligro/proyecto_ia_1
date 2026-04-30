package ai

// requestOptions configura opciones adicionales para requests de IA
type requestOptions struct {
	Temperature float32
	MaxTokens   int
	JSONMode    bool
}

// Option es una función que configura requestOptions
type Option func(*requestOptions)

// WithTemperature configura la temperatura (0.0 a 1.0)
func WithTemperature(t float32) Option {
	return func(opts *requestOptions) {
		if t >= 0 && t <= 1 {
			opts.Temperature = t
		}
	}
}

// WithMaxTokens configura el máximo de tokens de respuesta
func WithMaxTokens(n int) Option {
	return func(opts *requestOptions) {
		if n > 0 {
			opts.MaxTokens = n
		}
	}
}

// WithJSONMode habilita modo JSON (si el provider lo soporta)
func WithJSONMode() Option {
	return func(opts *requestOptions) {
		opts.JSONMode = true
	}
}
