package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/i18n"
	"github.com/peligro/proyecto_ia_1/pkg/scanner"
	"github.com/peligro/proyecto_ia_1/pkg/report"
	"github.com/spf13/cobra"
)

var (
	scanType string
	scanDir  string
	scanURL  string
	output   string
	lang     string
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
	scanCmd.Flags().StringVarP(&output, "output", "o", "json", "Output format: json, markdown")
	scanCmd.Flags().StringVarP(&lang, "lang", "l", "en", "Output language: en, es")

	rootCmd.AddCommand(scanCmd)
}

func runScan() error {
	// Inicializar traductor con el idioma seleccionado
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
	default:
		return report.GenerateJSON(findings, scanType, target, i18n.T)
	}
}