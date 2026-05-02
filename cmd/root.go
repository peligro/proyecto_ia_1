package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Variables para versión (se setean desde main.go)
var (
	appVersion = "dev"
	appCommit  = "none"
	appDate    = "unknown"
)

// SetVersionInfo permite inyectar versión desde main.go
func SetVersionInfo(version, commit, date string) {
	appVersion = version
	appCommit = commit
	appDate = date
}

var rootCmd = &cobra.Command{
	Use:   "ai-audit",
	Short: "AI-powered security audit CLI",
	Long: fmt.Sprintf(`AI Audit Security Scanner v%s
Commit: %s
Built: %s

A security scanner for dependencies, web apps, and AI integrations with AI-powered explanations.

Features:
  • Scan npm/Go dependencies via OSV.dev
  • Web security headers, SSL/TLS, CORS checks
  • Gray-box auth testing (BOLA/BFLA detection)
  • AI-powered vulnerability explanations (Gemini, Mistral, OpenAI)
  • Multi-language reports (en/es/fr/pt/de)
  • Output: JSON, Markdown, PDF

Examples:
  ai-audit scan --type web --url https://tusitio.com --ai --output pdf
  ai-audit scan --type deps --dir ./mi-proyecto --lang es
  ai-audit scan --type auth --url https://api.tusitio.com --graybox --admin-token xxx --user-token yyy`,
		appVersion, appCommit, appDate),
	Version: appVersion, // ← Habilita el flag --version
	Run: func(cmd *cobra.Command, args []string) {
		// Si se ejecuta sin subcomando, mostrar ayuda
		_ = cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}