package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/report"
)
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies,omitempty"`
	DevDependencies map[string]string `json:"devDependencies,omitempty"`
}
// OSV API structures
type OSVQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

type OSVVulnerability struct {
	ID         string `json:"id"`
	Summary    string `json:"summary"`
	Details    string `json:"details"`
	Severity   []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
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
		pkgFindings, err := queryOSV(pkgName, cleanVersion(version), "npm")
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to query OSV for %s: %v\n", pkgName, err)
			continue
		}
		findings = append(findings, pkgFindings...)
	}

	// Scan dev dependencies
	for pkgName, version := range pkg.DevDependencies {
		pkgFindings, err := queryOSV(pkgName, cleanVersion(version), "npm")
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to query OSV for %s: %v\n", pkgName, err)
			continue
		}
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
			
			pkgFindings, err := queryOSV(pkgName, version, "Go")
			if err != nil {
				fmt.Printf("⚠️  Warning: Failed to query OSV for %s: %v\n", pkgName, err)
				continue
			}
			findings = append(findings, pkgFindings...)
		}
	}

	return findings, nil
}

func queryOSV(pkgName, version, ecosystem string) ([]report.Finding, error) {
	query := OSVQuery{}
	query.Package.Name = pkgName
	query.Package.Ecosystem = ecosystem
	query.Version = version

	queryBody, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	// OSV.dev API endpoint
	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(queryBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var osvResp OSVResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, err
	}

	var findings []report.Finding

	for _, vuln := range osvResp.Vulns {
		// Extract fixed version
		var fixedIn string
		for _, affected := range vuln.Affected {
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Fixed != "" {
						fixedIn = event.Fixed
						break
					}
				}
			}
		}

		// Extract CVSS score
		var cvss float64
		var severity report.Severity
		for _, s := range vuln.Severity {
			if s.Type == "CVSS_V3" {
				// Parse CVSS score from string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
				// For now, use a simple heuristic
				if strings.Contains(s.Score, "CVSS:3") {
					cvss = 7.5 // Default to high if CVSS v3 present
					severity = report.High
				}
			}
		}

		// Map severity
		if severity == "" {
			severity = report.Medium
		}

		// Extract references
		var references []string
		for _, ref := range vuln.References {
			references = append(references, ref.URL)
		}

		finding := report.Finding{
			ID:          vuln.ID,
			Title:       fmt.Sprintf("Vulnerability in %s: %s", pkgName, vuln.Summary),
			Description: vuln.Details,
			Severity:    severity,
			Category:    "dependency",
			Package:     pkgName,
			Version:     version,
			FixedIn:     fixedIn,
			CVE:         vuln.ID,
			CVSS:        cvss,
			References:  references,
			FoundAt:     time.Now(),
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func cleanVersion(v string) string {
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, ">")
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimPrefix(v, "v")
	return strings.TrimSpace(v)
}