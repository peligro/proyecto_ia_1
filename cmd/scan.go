package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/ai"
	"github.com/peligro/proyecto_ia_1/pkg/i18n"
	"github.com/peligro/proyecto_ia_1/pkg/report"
	"github.com/peligro/proyecto_ia_1/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	// Scan flags
	scanType string
	scanDir  string
	scanURL  string
	output   string
	lang     string

	// AI flags
	aiEnabled  bool
	aiProvider string
	aiAPIKey   string
	aiModel    string

	// Cache flags
	cacheAI  bool
	cacheDir string
	cacheTTL time.Duration

	// Gray-box auth flags
	graybox    bool
	adminToken string
	userToken  string
	endpoints  []string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for security vulnerabilities",
	Long:  `Scan dependencies, web applications, APIs, or perform gray-box auth testing for BOLA/BFLA detection`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan()
	},
}

func init() {
	// Scan flags
	scanCmd.Flags().StringVarP(&scanType, "type", "t", "deps", "Scan type: deps, web, api, auth")
	scanCmd.Flags().StringVarP(&scanDir, "dir", "d", ".", "Directory to scan")
	scanCmd.Flags().StringVarP(&scanURL, "url", "u", "", "URL to scan (for web/api/auth types)")
	scanCmd.Flags().StringVarP(&output, "output", "o", "json", "Output format: json, markdown, pdf")
	scanCmd.Flags().StringVarP(&lang, "lang", "l", "en", "Output language: en, es, fr, pt, de")

	// AI flags
	scanCmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-powered explanations")
	scanCmd.Flags().StringVar(&aiProvider, "provider", "gemini", "AI provider: gemini, mistral, deepseek, openai")
	scanCmd.Flags().StringVar(&aiAPIKey, "key", "", "API key (or use *_API_KEY env var)")
	scanCmd.Flags().StringVar(&aiModel, "model", "", "Specific model (optional, uses provider default)")

	// Cache flags
	scanCmd.Flags().BoolVar(&cacheAI, "cache-ai", true, "Enable caching of AI responses")
	scanCmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Directory for AI cache (default: ~/.ai-audit/cache)")
	scanCmd.Flags().DurationVar(&cacheTTL, "cache-ttl", 24*time.Hour, "Cache TTL for AI responses")

	// Gray-box auth flags
	scanCmd.Flags().BoolVar(&graybox, "graybox", false, "Enable gray-box auth testing (BOLA/BFLA detection)")
	scanCmd.Flags().StringVar(&adminToken, "admin-token", "", "Admin API token for auth comparison")
	scanCmd.Flags().StringVar(&userToken, "user-token", "", "User API token for auth comparison")
	scanCmd.Flags().StringSliceVar(&endpoints, "endpoints", []string{"/api/users", "/api/admin/settings", "/api/profile", "/api/data"}, "API endpoints to test for auth bypass")

	rootCmd.AddCommand(scanCmd)
}

func runScan() error {
	// Inicializar traductor
	i18n.T = i18n.NewTranslator(i18n.Lang(lang))

	var findings []report.Finding
	var err error

	switch scanType {
	case "deps":
		findings, err = scanDependencies()
	case "web":
		if scanURL == "" {
			return fmt.Errorf(i18n.T.Get("msg.error_url_required"))
		}
		findings, err = scanWeb(scanURL)
	case "auth":
		if scanURL == "" {
			return fmt.Errorf("--url flag is required for auth scan")
		}
		if adminToken == "" || userToken == "" {
			return fmt.Errorf("gray-box auth requires --admin-token and --user-token")
		}
		findings, err = scanAuth(scanURL, adminToken, userToken, endpoints)
	case "api":
		return fmt.Errorf("api scanner not implemented yet")
	default:
		return fmt.Errorf(i18n.T.Get("msg.error_invalid_type"), scanType)
	}

	if err != nil {
		return err
	}

	// AI analysis (opcional)
	if aiEnabled && len(findings) > 0 {
		if err := runAIAnalysis(&findings); err != nil {
			fmt.Printf("⚠️  AI analysis warning: %v\n", err)
		}
	}

	return generateReport(findings)
}

func scanDependencies() ([]report.Finding, error) {
	absPath, err := filepath.Abs(scanDir)
	if err != nil {
		return nil, err
	}

	fmt.Printf(i18n.T.Get("msg.scanning_deps")+"\n", absPath)

	pkgJSONPath := filepath.Join(absPath, "package.json")
	if _, err := os.Stat(pkgJSONPath); err == nil {
		return scanner.ScanNpmDependencies(pkgJSONPath)
	}

	goModPath := filepath.Join(absPath, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		return scanner.ScanGoDependencies(goModPath)
	}

	return nil, fmt.Errorf(i18n.T.Get("msg.error_no_deps"))
}

func scanWeb(target string) ([]report.Finding, error) {
	fmt.Printf(i18n.T.Get("msg.scanning_web")+"\n", target)
	ws := scanner.NewWebScanner(10 * time.Second)
	return ws.Scan(target)
}

func scanAuth(baseURL, adminTok, userTok string, eps []string) ([]report.Finding, error) {
	fmt.Printf("🔐 Gray-Box Auth Scan: %s\n", baseURL)
	fmt.Printf("   Testing %d endpoints with admin vs user tokens...\n", len(eps))

	as := scanner.NewAuthScanner(adminTok, userTok, eps, 15*time.Second)
	return as.Scan(baseURL)
}

func runAIAnalysis(findings *[]report.Finding) error {
	cfg, err := ai.GetConfig(ai.Provider(aiProvider), aiAPIKey, aiModel)
	if err != nil {
		return fmt.Errorf("AI config error: %w", err)
	}

	// Inicializar cache
	if cacheDir == "" {
		home := os.Getenv("HOME")
		if home == "" {
			home = "/tmp"
		}
		cacheDir = filepath.Join(home, ".ai-audit", "cache")
	}
	aiCache := ai.NewCache(cacheDir, cacheTTL, cacheAI)

	fmt.Printf("🤖 AI: %s (key=%s, model=%s) | Cache: %v\n",
		cfg.Provider, cfg.MaskedKey(), cfg.Model, cacheAI)

	provider, err := ai.NewProvider(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize AI provider: %w", err)
	}

	totalTokens := 0
	totalCost := 0.0
	cacheHits := 0

	fmt.Println("🔍 Analizando vulnerabilidades con IA...")
	for i := range *findings {
		f := &(*findings)[i]

		// ← CONVERSIÓN: report.Severity → string
		prompt := ai.ExplainVulnerability(f.Title, string(f.Severity), f.Description, f.Category)
		cacheKey := ai.MakeKey(prompt, aiProvider, cfg.Model)

		// Intentar obtener del cache primero
		if cached, ok := aiCache.Get(cacheKey); ok {
			f.Recommendation = cached.Response
			totalTokens += cached.Tokens
			totalCost += cached.CostUSD
			cacheHits++
			fmt.Printf("  ✓ %s: [CACHE HIT]\n", f.ID)
			continue
		}

		// No hay cache → llamar a la API
		explanation, err := provider.ChatCompletion(
			context.Background(),
			prompt,
			ai.WithTemperature(0.3),
			ai.WithMaxTokens(800),
		)
		if err != nil {
			fmt.Printf("⚠️  AI failed for %s: %v\n", f.ID, err)
			continue
		}

		// Guardar en cache
		tokens, cost := provider.EstimateCost(prompt)
		_ = aiCache.Set(cacheKey, explanation, tokens, cost)

		f.Recommendation = explanation
		totalTokens += tokens
		totalCost += cost
		fmt.Printf("  ✓ %s: analizado [CACHE MISS]\n", f.ID)
	}

	// Resumen de cache
	if cacheAI {
		statsCount, statsSize, _ := aiCache.Stats()
		avgCost := 0.0
		if len(*findings) > 0 {
			avgCost = totalCost / float64(len(*findings))
		}
		fmt.Printf("\n📊 Cache: %d hits, %d entries (%.1f KB), ahorro estimado: $%.4f USD\n",
			cacheHits, statsCount, float64(statsSize)/1024, float64(cacheHits)*avgCost)
	} else {
		fmt.Printf("\n📊 Estimado total: ~%d tokens, costo: $%.4f USD\n", totalTokens, totalCost)
	}

	fmt.Println("✅ AI analysis complete\n")
	return nil
}

func generateReport(findings []report.Finding) error {
	target := scanDir
	if scanType == "web" && scanURL != "" {
		target = scanURL
	} else if scanType == "auth" && scanURL != "" {
		target = scanURL
	}

	switch output {
	case "json":
		return report.GenerateJSON(findings, scanType, target, i18n.T)
	case "markdown":
		return report.GenerateMarkdown(findings, scanType, target, i18n.T)
	case "pdf":
		return report.GeneratePDF(findings, scanType, target)
	default:
		return report.GenerateJSON(findings, scanType, target, i18n.T)
	}
}