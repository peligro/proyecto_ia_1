package report

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
	"os"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// GeneratePDF genera un reporte PDF profesional
func GeneratePDF(findings []Finding, scanType, target string) error {
	htmlContent := generateHTML(findings, scanType, target)
	
	// Crear servidor HTTP temporal para servir el HTML
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlContent)
	}))
	defer server.Close()
	
	// Configurar Chrome headless
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
	)
	
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	
	// Navegar al URL HTTP y generar PDF
	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(server.URL),
		chromedp.Sleep(2*time.Second), // Esperar renderizado de CSS/JS
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			buf, _, err = page.PrintToPDF().
				WithDisplayHeaderFooter(false).
				WithMarginTop(0.5).
				WithMarginBottom(0.5).
				WithMarginLeft(0.5).
				WithMarginRight(0.5).
				WithPrintBackground(true).
				Do(ctx)
			return err
		}),
	); err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}
	
	// Guardar PDF
	pdfPath := "report.pdf"
	if err := writeFileAtomic(pdfPath, buf, 0644); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}
	
	fmt.Printf("✅ Reporte PDF guardado en %s\n", pdfPath)
	return nil
}

// writeFileAtomic escribe el archivo de forma atómica (evita corrupción)
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func generateHTML(findings []Finding, scanType, target string) string {
	summary := calculateSummary(findings)
	
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe de Vulnerabilidades - %s</title>
    <style>
        @page { size: A4; margin: 15mm; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; color: #333; background: #fff; }
        .header { text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin: 0 0 10px 0; font-size: 28px; }
        .header .subtitle { color: #7f8c8d; font-size: 14px; }
        .header .target { color: #34495e; font-size: 13px; margin-top: 5px; font-weight: 500; }
        .section { margin-bottom: 35px; page-break-inside: avoid; }
        .section h2 { color: #2c3e50; border-left: 4px solid #3498db; padding-left: 12px; margin: 0 0 15px 0; font-size: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 15px 0; }
        .summary-card { padding: 15px 10px; border-radius: 6px; text-align: center; color: white; }
        .critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .high { background: linear-gradient(135deg, #e67e22, #d35400); }
        .medium { background: linear-gradient(135deg, #f1c40f, #f39c12); color: #333; }
        .low { background: linear-gradient(135deg, #27ae60, #229954); }
        .summary-card h3 { margin: 0 0 5px 0; font-size: 36px; font-weight: bold; }
        .summary-card p { margin: 0; font-size: 12px; font-weight: 500; }
        .finding { border: 1px solid #e0e0e0; border-radius: 6px; margin: 15px 0; padding: 15px; background: #fafafa; page-break-inside: avoid; }
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; flex-wrap: wrap; gap: 10px; }
        .finding-id { font-weight: bold; color: #2c3e50; font-size: 16px; font-family: monospace; background: #ecf0f1; padding: 3px 8px; border-radius: 4px; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; color: white; font-weight: bold; font-size: 11px; text-transform: uppercase; }
        .finding h3 { margin: 8px 0; color: #2c3e50; font-size: 15px; }
        .finding p { margin: 8px 0; line-height: 1.5; font-size: 13px; }
        .finding .label { font-weight: 600; color: #34495e; }
        .finding .value { color: #555; }
        .recommendation { background: #e8f6f3; border-left: 4px solid #1abc9c; padding: 12px; margin: 12px 0; border-radius: 0 4px 4px 0; }
        .recommendation strong { color: #16a085; }
        .evidence { background: #2c3e50; color: #ecf0f1; padding: 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 11px; overflow-x: auto; margin: 10px 0; white-space: pre-wrap; }
        .evidence-title { font-weight: bold; color: #3498db; margin-bottom: 8px; font-size: 12px; }
        table { width: 100%%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #3498db; color: white; font-weight: 600; }
        .footer { margin-top: 50px; text-align: center; color: #95a5a6; font-size: 11px; border-top: 1px solid #ecf0f1; padding-top: 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Informe de Análisis de Ciberseguridad</h1>
        <div class="subtitle">AI Audit Security Scanner</div>
        <div class="target">Target: %s | Tipo: %s | Fecha: %s</div>
    </div>

    <div class="section">
        <h2>📊 Resumen Ejecutivo</h2>
        <p style="font-size:13px;line-height:1.6;margin:10px 0;">
            En el presente informe se detalla el análisis de ciberseguridad efectuado sobre el objetivo <strong>%s</strong>. 
            Las pruebas se realizaron bajo la modalidad de análisis automatizado y manual, evaluando vulnerabilidades comunes 
            OWASP Top 10, configuración de seguridad, y buenas prácticas de desarrollo seguro.
        </p>
        
        <div class="summary-grid">
            <div class="summary-card critical">
                <h3>%d</h3>
                <p>Críticas</p>
            </div>
            <div class="summary-card high">
                <h3>%d</h3>
                <p>Altas</p>
            </div>
            <div class="summary-card medium">
                <h3>%d</h3>
                <p>Medias</p>
            </div>
            <div class="summary-card low">
                <h3>%d</h3>
                <p>Bajas</p>
            </div>
        </div>
        
        <p style="margin:15px 0;font-size:13px;"><strong>Total de vulnerabilidades:</strong> %d</p>
    </div>

    <div class="section">
        <h2>🎯 Detalle de Vulnerabilidades</h2>
        %s
    </div>

    <div class="footer">
        <p><strong>AI Audit Security Scanner</strong> | https://github.com/peligro/proyecto_ia_1</p>
        <p>Este informe es confidencial y destinado únicamente para el equipo de seguridad autorizado.<br>
        Generado automáticamente el %s</p>
    </div>
</body>
</html>`,
		target,
		target,
		scanType,
		time.Now().Format("2006-01-02"),
		target,
		summary.Critical,
		summary.High,
		summary.Medium,
		summary.Low,
		len(findings),
		generateFindingsHTML(findings),
		time.Now().Format("2006-01-02 15:04:05"),
	)
}

func generateFindingsHTML(findings []Finding) string {
	if len(findings) == 0 {
		return `<p style="font-size:13px;color:#7f8c8d;">No se identificaron vulnerabilidades en este escaneo.</p>`
	}
	
	html := ""
	for _, f := range findings {
		evidenceHTML := ""
		if len(f.Evidence) > 0 {
			evidenceHTML += `<div class="evidence-title">📋 Evidencia:</div>`
			for _, ev := range f.Evidence {
				evidenceHTML += fmt.Sprintf(`<div class="evidence">%s</div>`, escapeHTML(ev))
			}
		}
		
		recHTML := ""
		if f.Recommendation != "" {
			recHTML = fmt.Sprintf(`<div class="recommendation"><strong>💡 Recomendación:</strong> %s</div>`, f.Recommendation)
		}
		
		componentHTML := ""
		if f.Component != "" {
			componentHTML = fmt.Sprintf(`<p><span class="label">Componente:</span> <span class="value">%s</span></p>`, f.Component)
		}
		
		cveHTML := ""
		if f.CVE != "" {
			cveHTML = fmt.Sprintf(`<p><span class="label">CVE/ID:</span> <span class="value">%s</span></p>`, f.CVE)
		}
		
		html += fmt.Sprintf(`
        <div class="finding">
            <div class="finding-header">
                <span class="finding-id">%s</span>
                <span class="severity-badge" style="background:%s">%s</span>
            </div>
            <h3>%s</h3>
            <p><span class="label">Descripción:</span> %s</p>
            <p><span class="label">Categoría:</span> %s</p>
            %s%s%s
            %s
        </div>`,
			f.ID,
			getSeverityColor(f.Severity),
			f.Severity,
			f.Title,
			f.Description,
			f.Category,
			componentHTML,
			cveHTML,
			recHTML,
			evidenceHTML,
		)
	}
	return html
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func getSeverityColor(severity Severity) string {
	switch severity {
	case "CRITICAL":
		return "#e74c3c"
	case "HIGH":
		return "#e67e22"
	case "MEDIUM":
		return "#f1c40f"
	case "LOW":
		return "#27ae60"
	default:
		return "#95a5a6"
	}
}

func calculateSummary(findings []Finding) Summary {
	summary := Summary{}
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			summary.Critical++
		case "HIGH":
			summary.High++
		case "MEDIUM":
			summary.Medium++
		case "LOW":
			summary.Low++
		}
	}
	return summary
}