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
	scanType     string
	scanDir      string
	scanURL      string
	output       string
	lang         string
	aiEnabled    bool
	aiProvider   string
	aiAPIKey     string
	aiModel      string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for security vulnerabilities",
	Long:  `Scan dependencies, web applications, or AI integrations for security issues`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan()
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanType, "type", "t", "deps", "Scan type: deps, web, api")
	scanCmd.Flags().StringVarP(&scanDir, "dir", "d", ".", "Directory to scan")
	scanCmd.Flags().StringVarP(&scanURL, "url", "u", "", "URL to scan (for web/api types)")
	scanCmd.Flags().StringVarP(&output, "output", "o", "json", "Output format: json, markdown, pdf")
	scanCmd.Flags().StringVarP(&lang, "lang", "l", "en", "Output language: en, es, fr, pt, de")
	
	// AI flags
	scanCmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-powered explanations")
	scanCmd.Flags().StringVar(&aiProvider, "provider", "gemini", "AI provider: gemini, mistral, deepseek, openai, claude")
	scanCmd.Flags().StringVar(&aiAPIKey, "key", "", "API key (or use *_API_KEY env var)")
	scanCmd.Flags().StringVar(&aiModel, "model", "", "Specific model (optional, uses provider default)")

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
	case "api":
		return fmt.Errorf("api scanner not implemented yet")
	default:
		return fmt.Errorf(i18n.T.Get("msg.error_invalid_type"), scanType)
	}

	if err != nil {
		return err
	}

	// AI analysis (opcional)
	if aiEnabled {
		if err := runAIAnalysis(&findings); err != nil {
			fmt.Printf("⚠️  AI analysis warning: %v\n", err)
			// No fallamos el scan si AI falla, solo advertimos
		}
	}

	return generateReport(findings)
}

func runAIAnalysis(findings *[]report.Finding) error {
	cfg, err := ai.GetConfig(ai.Provider(aiProvider), aiAPIKey, aiModel)
	if err != nil {
		return fmt.Errorf("AI config error: %w", err)
	}
	
	fmt.Printf("🤖 AI: %s (key=%s, model=%s)\n", cfg.Provider, cfg.MaskedKey(), cfg.Model)
	
	provider, err := ai.NewProvider(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize AI provider: %w", err)
	}
	
	// Estimación de costo
	totalTokens := 0
	totalCost := 0.0
	for _, f := range *findings {
		prompt := ai.ExplainVulnerability(f.Title, string(f.Severity), f.Description, f.Category)
		tokens, cost := provider.EstimateCost(prompt)
		totalTokens += tokens
		totalCost += cost
	}
	fmt.Printf("📊 Estimado: ~%d tokens, costo: $%.4f USD\n\n", totalTokens, totalCost)
	
	// Analizar cada finding
	fmt.Println("🔍 Analizando vulnerabilidades con IA...")
	for i := range *findings {
		prompt := ai.ExplainVulnerability(
			(*findings)[i].Title,
			string((*findings)[i].Severity),
			(*findings)[i].Description,
			(*findings)[i].Category,
		)
		
		explanation, err := provider.ChatCompletion(
			context.Background(), 
			prompt, 
			ai.WithTemperature(0.3),
			ai.WithMaxTokens(800),
		)
		if err != nil {
			fmt.Printf("⚠️  AI failed for %s: %v\n", (*findings)[i].ID, err)
			continue
		}
		
		// Agregar explicación al finding
		(*findings)[i].Recommendation = explanation
		fmt.Printf("  ✓ %s: analizado\n", (*findings)[i].ID)
	}
	
	fmt.Println("✅ AI analysis complete\n")
	return nil
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

func generateReport(findings []report.Finding) error {
	target := scanDir
	if scanType == "web" && scanURL != "" {
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