package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"github.com/peligro/proyecto_ia_1/pkg/report"
)

// package.json structure
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies,omitempty"`
	DevDependencies map[string]string `json:"devDependencies,omitempty"`
}

func ScanNpmDependencies(pkgJSONPath string) ([]report.Finding, error) {
	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return nil, err
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var findings []report.Finding

	// Scan dependencies
	for pkgName, version := range pkg.Dependencies {
		pkgFindings := checkVulnerability(pkgName, cleanVersion(version))
		findings = append(findings, pkgFindings...)
	}

	// Scan dev dependencies
	for pkgName, version := range pkg.DevDependencies {
		pkgFindings := checkVulnerability(pkgName, cleanVersion(version))
		findings = append(findings, pkgFindings...)
	}

	return findings, nil
}

func ScanGoDependencies(goModPath string) ([]report.Finding, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	var findings []report.Finding
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") || strings.HasPrefix(line, "//") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			pkgName := parts[0]
			version := cleanVersion(parts[1])
			
			pkgFindings := checkVulnerability(pkgName, version)
			findings = append(findings, pkgFindings...)
		}
	}

	return findings, nil
}

func checkVulnerability(pkgName, version string) []report.Finding {
	// This is a placeholder - in production, you'd query OSV.dev API
	// For now, we'll return mock findings for demonstration
	
	var findings []report.Finding

	// Example: Check for known vulnerable packages
	vulnerablePackages := map[string]struct {
		Severity report.Severity
		CVE      string
		FixedIn  string
		Desc     string
	}{
		"lodash": {
			Severity: report.High,
			CVE:      "CVE-2021-23337",
			FixedIn:  "4.17.21",
			Desc:     "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
		},
		"axios": {
			Severity: report.Medium,
			CVE:      "CVE-2021-3749",
			FixedIn:  "0.21.2",
			Desc:     "axios is vulnerable to Inefficient Regular Expression Complexity",
		},
		"express": {
			Severity: report.Low,
			CVE:      "CVE-2022-24999",
			FixedIn:  "4.17.3",
			Desc:     "Express before 4.17.3 allows Open Redirect attacks via the redirect function.",
		},
	}

	if vuln, exists := vulnerablePackages[pkgName]; exists {
		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("DEP-%s", pkgName),
			Title:       fmt.Sprintf("Vulnerable dependency: %s", pkgName),
			Description: vuln.Desc,
			Severity:    vuln.Severity,
			Category:    "dependency",
			Package:     pkgName,
			Version:     version,
			FixedIn:     vuln.FixedIn,
			CVE:         vuln.CVE,
			FoundAt:     time.Now(),
		})
	}

	return findings
}

func cleanVersion(v string) string {
	// Remove ^, ~, >=, etc.
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, ">")
	v = strings.TrimPrefix(v, "=")
	return strings.TrimSpace(v)
}
