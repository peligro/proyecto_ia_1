package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CacheEntry representa una entrada en el cache de AI
type CacheEntry struct {
	Response  string    `json:"response"`
	Tokens    int       `json:"tokens"`
	CostUSD   float64   `json:"cost_usd"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Cache maneja el cache de respuestas de AI en disco
type Cache struct {
	dir     string
	ttl     time.Duration
	enabled bool
}

// NewCache crea una nueva instancia de cache
func NewCache(cacheDir string, ttl time.Duration, enabled bool) *Cache {
	return &Cache{
		dir:     cacheDir,
		ttl:     ttl,
		enabled: enabled,
	}
}

// Get obtiene una respuesta cacheada si existe y no ha expirado
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	if !c.enabled {
		return nil, false
	}

	path := filepath.Join(c.dir, key+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	// Verificar expiración
	if time.Now().After(entry.ExpiresAt) {
		_ = os.Remove(path) // Limpiar entry expirado
		return nil, false
	}

	return &entry, true
}

// Set guarda una respuesta en el cache
func (c *Cache) Set(key string, response string, tokens int, costUSD float64) error {
	if !c.enabled {
		return nil
	}

	// Asegurar directorio
	if err := os.MkdirAll(c.dir, 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}

	entry := CacheEntry{
		Response:  response,
		Tokens:    tokens,
		CostUSD:   costUSD,
		ExpiresAt: time.Now().Add(c.ttl),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	path := filepath.Join(c.dir, key+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache entry: %w", err)
	}

	return nil
}

// Clear limpia todo el cache
func (c *Cache) Clear() error {
	if !c.enabled {
		return nil
	}
	return os.RemoveAll(c.dir)
}

// MakeKey genera una clave única para el cache basada en prompt+provider+model
func MakeKey(prompt, provider, model string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", prompt, provider, model)))
	return hex.EncodeToString(hash[:])
}

// Stats devuelve estadísticas del cache (para debug)
func (c *Cache) Stats() (count int, sizeBytes int64, err error) {
	if !c.enabled {
		return 0, 0, nil
	}

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0, 0, err
	}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		count++
		info, err := e.Info()
		if err == nil {
			sizeBytes += info.Size()
		}
	}
	return count, sizeBytes, nil
}
