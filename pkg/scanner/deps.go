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

	"github.com/joho/godotenv"
	"github.com/peligro/proyecto_ia_1/pkg/report"
)

// init carga variables de entorno desde .env si existe
func init() {
	// Carga .env desde el directorio actual o padre
	_ = godotenv.Load()      // ./ .env
	_ = godotenv.Load("../.env") // ../.env (para cuando se ejecuta desde cmd/)
}

// getConfig devuelve el valor de una env var con fallback
func getConfig(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

// getOSVEndpoint devuelve el endpoint de OSV con validación básica
func getOSVEndpoint() string {
	endpoint := getConfig("OSV_API_ENDPOINT", "https://api.osv.dev/v1/query")
	// Validación mínima: debe ser https y terminar en /query
	if !strings.HasPrefix(endpoint, "https://") || !strings.HasSuffix(endpoint, "/query") {
		// Log de advertencia pero no falla (fallback seguro)
		fmt.Fprintf(os.Stderr, "⚠️  Warning: OSV_API_ENDPOINT may be invalid, using default\n")
		return "https://api.osv.dev/v1/query"
	}
	return endpoint
}

// getOSVTimeout devuelve el timeout en segundos
func getOSVTimeout() time.Duration {
	timeoutStr := getConfig("OSV_API_TIMEOUT", "30")
	var timeout int
	fmt.Sscanf(timeoutStr, "%d", &timeout)
	if timeout <= 0 {
		timeout = 30
	}
	return time.Duration(timeout) * time.Second
}

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

	for pkgName, version := range pkg.Dependencies {
		pkgFindings, err := queryOSV(pkgName, cleanVersion(version), "npm")
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to query OSV for %s: %v\n", pkgName, err)
			continue
		}
		findings = append(findings, pkgFindings...)
	}

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

	endpoint := getOSVEndpoint()
	timeout := getOSVTimeout()

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(endpoint, "application/json", bytes.NewBuffer(queryBody))
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

		var cvss float64
		var severity report.Severity
		for _, s := range vuln.Severity {
			if s.Type == "CVSS_V3" {
				if strings.Contains(s.Score, "CVSS:3") {
					cvss = 7.5
					severity = report.High
				}
			}
		}

		if severity == "" {
			severity = report.Medium
		}

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