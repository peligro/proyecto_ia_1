package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"`
	File        string    `json:"file,omitempty"`
	Line        int       `json:"line,omitempty"`
	Package     string    `json:"package,omitempty"`
	Version     string    `json:"version,omitempty"`
	FixedIn     string    `json:"fixed_in,omitempty"`
	CVE         string    `json:"cve,omitempty"`
	CVSS        float64   `json:"cvss_score,omitempty"`
	References  []string  `json:"references,omitempty"`
	FoundAt     time.Time `json:"found_at"`
}

type Report struct {
	ScanType   string     `json:"scan_type"`
	Target     string     `json:"target"`
	ScannedAt  time.Time  `json:"scanned_at"`
	TotalFindings int     `json:"total_findings"`
	Findings   []Finding  `json:"findings"`
}

func GenerateJSON(findings []Finding) error {
	report := Report{
		ScanType:      "dependencies",
		Target:        ".",
		ScannedAt:     time.Now(),
		TotalFindings: len(findings),
		Findings:      findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(data))

	// Save to file
	err = os.WriteFile("report.json", data, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("\n✅ Report saved to report.json\n")
	return nil
}

func GenerateMarkdown(findings []Finding) error {
	md := fmt.Sprintf("# Security Audit Report\n\n")
	md += fmt.Sprintf("**Scanned at:** %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	md += fmt.Sprintf("**Total findings:** %d\n\n", len(findings))

	// Summary by severity
	critical := 0
	high := 0
	medium := 0
	low := 0

	for _, f := range findings {
		switch f.Severity {
		case Critical:
			critical++
		case High:
			high++
		case Medium:
			medium++
		case Low:
			low++
		}
	}

	md += "## Summary\n\n"
	md += fmt.Sprintf("- 🔴 Critical: %d\n", critical)
	md += fmt.Sprintf("- 🟠 High: %d\n", high)
	md += fmt.Sprintf("- 🟡 Medium: %d\n", medium)
	md += fmt.Sprintf("- 🟢 Low: %d\n\n", low)

	md += "## Findings\n\n"

	for i, f := range findings {
		md += fmt.Sprintf("### %d. %s\n\n", i+1, f.Title)
		md += fmt.Sprintf("**Severity:** %s\n\n", f.Severity)
		md += fmt.Sprintf("**Description:** %s\n\n", f.Description)
		
		if f.Package != "" {
			md += fmt.Sprintf("**Package:** %s@%s\n\n", f.Package, f.Version)
		}
		
		if f.FixedIn != "" {
			md += fmt.Sprintf("**Fix:** Upgrade to %s\n\n", f.FixedIn)
		}

		if len(f.References) > 0 {
			md += "**References:**\n"
			for _, ref := range f.References {
				md += fmt.Sprintf("- %s\n", ref)
			}
			md += "\n"
		}

		md += "---\n\n"
	}

	fmt.Println(md)

	// Save to file
	err := os.WriteFile("report.md", []byte(md), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Report saved to report.md\n")
	return nil
}
