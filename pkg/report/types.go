package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/i18n"
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
	Component   string    `json:"component,omitempty"`
	File        string    `json:"file,omitempty"`
	Line        int       `json:"line,omitempty"`
	Package     string    `json:"package,omitempty"`
	Version     string    `json:"version,omitempty"`
	FixedIn     string    `json:"fixed_in,omitempty"`
	CVE         string    `json:"cve,omitempty"`
	CVSS        float64   `json:"cvss_score,omitempty"`
	References  []string  `json:"references,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	Evidence    []string  `json:"evidence,omitempty"`
	FoundAt     time.Time `json:"found_at"`
}

type Report struct {
	ScanType      string    `json:"scan_type"`
	Target        string    `json:"target"`
	ScannedAt     time.Time `json:"scanned_at"`
	TotalFindings int       `json:"total_findings"`
	Findings      []Finding `json:"findings"`
	Summary       Summary   `json:"summary"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func GenerateJSON(findings []Finding, scanType, target string, t *i18n.Translator) error {
	// Traducir findings si es necesario
	translated := make([]Finding, len(findings))
	for i, f := range findings {
		translated[i] = translateFinding(f, t)
	}

	// Calcular resumen
	summary := Summary{}
	for _, f := range translated {
		switch f.Severity {
		case Critical:
			summary.Critical++
		case High:
			summary.High++
		case Medium:
			summary.Medium++
		case Low:
			summary.Low++
		}
	}

	report := Report{
		ScanType:      scanType,
		Target:        target,
		ScannedAt:     time.Now(),
		TotalFindings: len(translated),
		Findings:      translated,
		Summary:       summary,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(data))

	err = os.WriteFile("report.json", data, 0644)
	if err != nil {
		return err
	}

	fmt.Printf(i18n.T.Get("msg.report_saved")+"\n", "report.json")
	return nil
}

func GenerateMarkdown(findings []Finding, scanType, target string, t *i18n.Translator) error {
	translated := make([]Finding, len(findings))
	for i, f := range findings {
		translated[i] = translateFinding(f, t)
	}

	summary := Summary{}
	for _, f := range translated {
		switch f.Severity {
		case Critical:
			summary.Critical++
		case High:
			summary.High++
		case Medium:
			summary.Medium++
		case Low:
			summary.Low++
		}
	}

	md := fmt.Sprintf("# %s\n\n", t.Get("report.title"))
	md += fmt.Sprintf("**%s:** %s  \n", t.Get("report.scan_type"), scanType)
	md += fmt.Sprintf("**%s:** %s  \n", t.Get("report.target"), target)
	md += fmt.Sprintf("**%s:** %s  \n\n", t.Get("report.scanned_at"), time.Now().Format("2006-01-02 15:04:05"))
	md += fmt.Sprintf("**%s:** %d  \n\n", t.Get("report.total_findings"), len(translated))

	md += fmt.Sprintf("## %s\n\n", t.Get("report.summary"))
	md += fmt.Sprintf("- 🔴 %s: %d\n", t.Get("severity.critical"), summary.Critical)
	md += fmt.Sprintf("- 🟠 %s: %d\n", t.Get("severity.high"), summary.High)
	md += fmt.Sprintf("- 🟡 %s: %d\n", t.Get("severity.medium"), summary.Medium)
	md += fmt.Sprintf("- 🟢 %s: %d\n\n", t.Get("severity.low"), summary.Low)

	md += fmt.Sprintf("## %s\n\n", t.Get("report.findings"))

	for i, f := range translated {
		md += fmt.Sprintf("### %d. %s\n\n", i+1, f.Title)
		md += fmt.Sprintf("**%s:** `%s`  \n", t.Get("finding.id"), f.ID)
		md += fmt.Sprintf("**%s:** %s  \n", t.Get("finding.severity"), f.Severity)
		md += fmt.Sprintf("**%s:** %s  \n\n", t.Get("finding.description"), f.Description)

		if f.Component != "" {
			md += fmt.Sprintf("**%s:** `%s`  \n", t.Get("finding.component"), f.Component)
		}
		if f.Package != "" {
			md += fmt.Sprintf("**%s:** %s@%s  \n", t.Get("finding.package"), f.Package, f.Version)
		}
		if f.FixedIn != "" {
			md += fmt.Sprintf("**%s:** %s  \n\n", t.Get("finding.fix"), f.FixedIn)
		}
		if f.Recommendation != "" {
			md += fmt.Sprintf("**%s:** %s  \n\n", t.Get("finding.recommendation"), f.Recommendation)
		}
		if len(f.References) > 0 {
			md += fmt.Sprintf("**%s:**\n", t.Get("finding.references"))
			for _, ref := range f.References {
				md += fmt.Sprintf("- %s\n", ref)
			}
			md += "\n"
		}
		if len(f.Evidence) > 0 {
			md += fmt.Sprintf("**%s:**\n", t.Get("finding.evidence"))
			for _, ev := range f.Evidence {
				md += fmt.Sprintf("```\n%s\n```\n\n", ev)
			}
		}
		md += "---\n\n"
	}

	fmt.Println(md)

	err := os.WriteFile("report.md", []byte(md), 0644)
	if err != nil {
		return err
	}

	fmt.Printf(i18n.T.Get("msg.report_saved")+"\n", "report.md")
	return nil
}

func translateFinding(f Finding, t *i18n.Translator) Finding {
	// Si el finding ya viene traducido desde el scanner, no hacer nada
	// Esta función es para fallback si algún finding no fue traducido
	return f
}