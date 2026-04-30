package report

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/jung-kurt/gofpdf"
)

// GeneratePDF genera un reporte PDF profesional
// Intenta chromedp primero (alta calidad con CSS), fallback a gofpdf (básico pero funcional)
func GeneratePDF(findings []Finding, scanType, target string) error {
	// Intentar chromedp primero (PDF profesional con CSS)
	if err := generatePDFWithChrome(findings, scanType, target); err == nil {
		return nil
	}
	
	// Fallback a gofpdf si chromedp falla
	return generatePDFWithGofpdf(findings, scanType, target)
}

// generatePDFWithChrome intenta generar PDF con chromedp (Chrome headless)
func generatePDFWithChrome(findings []Finding, scanType, target string) error {
	if !isChromeAvailable() {
		return fmt.Errorf("Chrome/Chromium not found")
	}

	htmlContent := generateHTML(findings, scanType, target)
	
	// Servidor HTTP temporal para servir el HTML
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlContent)
	}))
	defer server.Close()
	
	// Configurar Chrome headless con flags para Docker
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("allow-file-access-from-files", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("remote-debugging-port", "0"),
		chromedp.Flag("window-size", "1920,1080"),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
	)
	
	// 1. Crear allocator
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()
	
	// 2. Crear contexto chromedp (devuelve 2 valores)
	chromedpCtx, chromedpCancel := chromedp.NewContext(allocCtx)
	defer chromedpCancel()
	
	// 3. Agregar timeout al contexto chromedp
	ctx, timeoutCancel := context.WithTimeout(chromedpCtx, 30*time.Second)
	defer timeoutCancel()
	
	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Navigate(server.URL),
		chromedp.Sleep(2*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			buf, _, err = page.PrintToPDF().
				WithDisplayHeaderFooter(false).
				WithMarginTop(0.4).
				WithMarginBottom(0.4).
				WithMarginLeft(0.4).
				WithMarginRight(0.4).
				WithPrintBackground(true).
				Do(ctx)
			return err
		}),
	); err != nil {
		return fmt.Errorf("chromedp failed: %w", err)
	}
	
	pdfPath := "report.pdf"
	if err := os.WriteFile(pdfPath, buf, 0644); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}
	
	fmt.Printf("✅ Reporte PDF guardado en %s\n", pdfPath)
	return nil
}

// generatePDFWithGofpdf genera PDF básico como fallback (sin Chrome)
// Nota: Helvetica no soporta UTF-8 nativo, los acentos se verán como "?" o caracteres extraños
// Para UTF-8 perfecto, instalar Chromium y que funcione chromedp
func generatePDFWithGofpdf(findings []Finding, scanType, target string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetMargins(15, 15, 15)
	
	// Usar Helvetica directamente (sin AddUTF8Font para evitar dependencias externas)
	pdf.SetFont("Helvetica", "", 10)
	
	// === HEADER ===
	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "Informe de Analisis de Ciberseguridad")  // Sin acentos para evitar problemas
	pdf.Ln(6)
	
	pdf.SetFont("Helvetica", "", 9)
	pdf.Cell(0, 5, fmt.Sprintf("AI Audit Security Scanner | Target: %s", target))
	pdf.Ln(4)
	pdf.Cell(0, 5, fmt.Sprintf("Fecha: %s", time.Now().Format("2006-01-02 15:04:05")))
	pdf.Ln(8)
	
	// === RESUMEN EJECUTIVO ===
	summary := calculateSummary(findings)
	
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Resumen Ejecutivo")
	pdf.Ln(5)
	
	pdf.SetFont("Helvetica", "", 9)
	summaryText := fmt.Sprintf("Total vulnerabilidades: %d (Criticas: %d, Altas: %d, Medias: %d, Bajas: %d)",
		len(findings), summary.Critical, summary.High, summary.Medium, summary.Low)
	pdf.MultiCell(0, 4, summaryText, "", "L", false)
	pdf.Ln(4)
	
	// === DETALLE DE VULNERABILIDADES ===
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Detalle de Vulnerabilidades")
	pdf.Ln(5)
	
	for _, f := range findings {
		// ID y título (limpiar acentos para Helvetica)
		pdf.SetFont("Helvetica", "B", 9)
		title := stripAccents(f.Title)
		pdf.Cell(0, 5, fmt.Sprintf("[%s] %s", f.ID, title))
		pdf.Ln(4)
		
		// Metadata
		pdf.SetFont("Helvetica", "", 8)
		category := stripAccents(f.Category)
		metaText := fmt.Sprintf("Severidad: %s | Categoria: %s", f.Severity, category)
		pdf.MultiCell(0, 3.5, metaText, "", "L", false)
		
		// Descripción (limpiar markdown y acentos)
		cleanDesc := stripAccents(cleanMarkdownForPDF(f.Description))
		pdf.MultiCell(0, 3.5, "Descripcion: "+cleanDesc, "", "L", false)
		
		// Recomendación (si existe)
		if f.Recommendation != "" {
			cleanRec := stripAccents(cleanMarkdownForPDF(f.Recommendation))
			pdf.MultiCell(0, 3.5, "Recomendacion: "+cleanRec, "", "L", false)
		}
		
		// Separador
		pdf.Ln(2)
		pdf.Line(15, pdf.GetY(), 195, pdf.GetY())
		pdf.Ln(3)
		
		// Nueva página si se acaba el espacio
		if pdf.GetY() > 250 {
			pdf.AddPage()
		}
	}
	
	// === FOOTER ===
	pdf.SetY(-15)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.Cell(0, 5, "Generado por AI Audit Security Scanner | github.com/peligro/proyecto_ia_1")
	
	// Guardar PDF
	pdfPath := "report.pdf"
	if err := pdf.OutputFileAndClose(pdfPath); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}
	
	fmt.Printf("✅ Reporte PDF guardado en %s (modo basico)\n", pdfPath)
	return nil
}

// stripAccents reemplaza caracteres acentuados por equivalentes sin acento para compatibilidad con Helvetica
func stripAccents(s string) string {
	replacements := map[string]string{
		"á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u",
		"Á": "A", "É": "E", "Í": "I", "Ó": "O", "Ú": "U",
		"ñ": "n", "Ñ": "N", "ü": "u", "Ü": "U",
	}
	for accented, plain := range replacements {
		s = strings.ReplaceAll(s, accented, plain)
	}
	return s
}

// cleanMarkdownForPDF limpia markdown para renderizado en PDF plano
func cleanMarkdownForPDF(text string) string {
	// Remover bloques de código markdown
	text = strings.ReplaceAll(text, "```markdown", "")
	text = strings.ReplaceAll(text, "```", "")
	
	// Remover formatos markdown básicos
	text = strings.ReplaceAll(text, "**", "")
	text = strings.ReplaceAll(text, "__", "")
	text = strings.ReplaceAll(text, "*", "")
	text = strings.ReplaceAll(text, "_", "")
	
	// Remover encabezados markdown
	lines := strings.Split(text, "\n")
	cleaned := []string{}
	for _, line := range lines {
		line = strings.TrimPrefix(line, "# ")
		line = strings.TrimPrefix(line, "## ")
		line = strings.TrimPrefix(line, "### ")
		line = strings.TrimPrefix(line, "#### ")
		if strings.TrimSpace(line) != "" {
			cleaned = append(cleaned, line)
		}
	}
	
	return strings.Join(cleaned, " ")
}

// isChromeAvailable verifica si Chrome/Chromium está en PATH
func isChromeAvailable() bool {
	binaries := []string{"chromium", "chromium-browser", "google-chrome", "chrome"}
	for _, bin := range binaries {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
	}
	return false
}

// generateHTML genera el HTML con CSS profesional para chromedp
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
            Análisis de ciberseguridad sobre <strong>%s</strong>. Evaluación de vulnerabilidades OWASP Top 10, configuración de seguridad y buenas prácticas.
        </p>
        <div class="summary-grid">
            <div class="summary-card critical"><h3>%d</h3><p>Críticas</p></div>
            <div class="summary-card high"><h3>%d</h3><p>Altas</p></div>
            <div class="summary-card medium"><h3>%d</h3><p>Medias</p></div>
            <div class="summary-card low"><h3>%d</h3><p>Bajas</p></div>
        </div>
        <p style="margin:15px 0;font-size:13px;"><strong>Total:</strong> %d vulnerabilidades</p>
    </div>
    <div class="section">
        <h2>🎯 Detalle de Vulnerabilidades</h2>
        %s
    </div>
    <div class="footer">
        <p><strong>AI Audit Security Scanner</strong> | https://github.com/peligro/proyecto_ia_1</p>
        <p>Confidencial. Generado: %s</p>
    </div>
</body>
</html>`,
		target, target, scanType, time.Now().Format("2006-01-02"),
		target, summary.Critical, summary.High, summary.Medium, summary.Low,
		len(findings), generateFindingsHTML(findings), time.Now().Format("2006-01-02 15:04:05"),
	)
}

func generateFindingsHTML(findings []Finding) string {
	if len(findings) == 0 {
		return `<p style="font-size:13px;color:#7f8c8d;">No se identificaron vulnerabilidades.</p>`
	}
	html := ""
	for _, f := range findings {
		recHTML := ""
		if f.Recommendation != "" {
			cleanRec := strings.ReplaceAll(f.Recommendation, "```markdown", "")
			cleanRec = strings.ReplaceAll(cleanRec, "```", "")
			recHTML = fmt.Sprintf(`<div class="recommendation"><strong>💡 Recomendación:</strong><br>%s</div>`, cleanRec)
		}
		html += fmt.Sprintf(`
        <div class="finding">
            <div class="finding-header">
                <span class="finding-id">%s</span>
                <span class="severity-badge" style="background:%s">%s</span>
            </div>
            <h3>%s</h3>
            <p><strong>Descripción:</strong> %s</p>
            <p><strong>Categoría:</strong> %s | <strong>Componente:</strong> %s</p>
            %s
        </div>`,
			f.ID, getSeverityColor(f.Severity), f.Severity, f.Title, f.Description, f.Category, f.Component, recHTML)
	}
	return html
}

func getSeverityColor(severity Severity) string {
	switch severity {
	case "CRITICAL": return "#e74c3c"
	case "HIGH": return "#e67e22"
	case "MEDIUM": return "#f1c40f"
	case "LOW": return "#27ae60"
	default: return "#95a5a6"
	}
}

func calculateSummary(findings []Finding) Summary {
	summary := Summary{}
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL": summary.Critical++
		case "HIGH": summary.High++
		case "MEDIUM": summary.Medium++
		case "LOW": summary.Low++
		}
	}
	return summary
}