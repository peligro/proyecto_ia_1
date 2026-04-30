package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/scanner"
	"github.com/peligro/proyecto_ia_1/pkg/report"
	"github.com/spf13/cobra"
)

var (
	scanType string
	scanDir  string
	scanURL  string
	output   string
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

	rootCmd.AddCommand(scanCmd)
}

func runScan() error {
	var findings []report.Finding
	var err error

	switch scanType {
	case "deps":
		findings, err = scanDependencies()
	case "web":
		if scanURL == "" {
			return fmt.Errorf("--url flag is required for web scan")
		}
		findings, err = scanWeb(scanURL)
	case "api":
		return fmt.Errorf("api scanner not implemented yet")
	default:
		return fmt.Errorf("invalid scan type: %s", scanType)
	}

	if err != nil {
		return err
	}

	// Generate report
	return generateReport(findings)
}

func scanDependencies() ([]report.Finding, error) {
	absPath, err := filepath.Abs(scanDir)
	if err != nil {
		return nil, err
	}

	fmt.Printf("🔍 Scanning dependencies in %s...\n", absPath)

	// Try to find package.json
	pkgJSONPath := filepath.Join(absPath, "package.json")
	if _, err := os.Stat(pkgJSONPath); err == nil {
		return scanner.ScanNpmDependencies(pkgJSONPath)
	}

	// Try to find go.mod
	goModPath := filepath.Join(absPath, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		return scanner.ScanGoDependencies(goModPath)
	}

	return nil, fmt.Errorf("no supported dependency file found (package.json or go.mod)")
}

func scanWeb(target string) ([]report.Finding, error) {
	fmt.Printf("🔍 Scanning web application: %s...\n", target)

	// Instanciar scanner con timeout de 10 segundos
	ws := scanner.NewWebScanner(10 * time.Second)
	return ws.Scan(target)
}

func generateReport(findings []report.Finding) error {
	// Determinar el target correcto
	target := scanDir
	if scanType == "web" && scanURL != "" {
		target = scanURL
	}

	switch output {
	case "json":
		return report.GenerateJSON(findings, scanType, target)
	case "markdown":
		return report.GenerateMarkdown(findings, scanType, target)
	default:
		return report.GenerateJSON(findings, scanType, target)
	}
}