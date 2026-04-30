package i18n

// Lang representa un idioma soportado
type Lang string

const (
	EN Lang = "en"
	ES Lang = "es"
)

// DefaultLang es el idioma por defecto si no se especifica
const DefaultLang = EN

// T es el traductor global (inicializado en init)
var T *Translator

// Translator maneja las traducciones
type Translator struct {
	lang Lang
	dict map[Lang]map[string]string
}

// NewTranslator crea un nuevo traductor
func NewTranslator(lang Lang) *Translator {
	if lang == "" {
		lang = DefaultLang
	}
	return &Translator{
		lang: lang,
		dict: loadDictionary(),
	}
}

// Traduce una key al idioma actual, fallback a EN, luego a la key misma
func (t *Translator) Get(key string) string {
	// Intentar en el idioma actual
	if val, ok := t.dict[t.lang][key]; ok {
		return val
	}
	// Fallback a inglés
	if val, ok := t.dict[EN][key]; ok {
		return val
	}
	// Último recurso: devolver la key
	return key
}

// SetLang cambia el idioma activo
func (t *Translator) SetLang(lang Lang) {
	if lang == "" {
		lang = DefaultLang
	}
	t.lang = lang
}

// loadDictionary carga todas las traducciones
func loadDictionary() map[Lang]map[string]string {
	return map[Lang]map[string]string{
		EN: enDict(),
		ES: esDict(),
	}
}

// === DICCIONARIO INGLÉS ===
func enDict() map[string]string {
	return map[string]string{
		// CLI messages
		"msg.scanning_deps":    "🔍 Scanning dependencies in %s...",
		"msg.scanning_web":     "🔍 Scanning web application: %s...",
		"msg.report_saved":     "✅ Report saved to %s",
		"msg.warning_osv":      "⚠️  Warning: Failed to query OSV for %s: %v",
		"msg.error_invalid_url": "invalid URL: %w",
		"msg.error_fetch":      "Could not retrieve %s: %v",
		"msg.error_no_deps":    "no supported dependency file found (package.json or go.mod)",
		"msg.error_url_required": "--url flag is required for web scan",
		"msg.error_invalid_type": "invalid scan type: %s",

		// Finding titles
		"title.web_no_waf":                    "No Web Application Firewall detected",
		"title.web_missing_header":            "Missing security header: %s",
		"title.web_disclosure":                "Information disclosure via %s header",
		"title.web_cache_control":             "Missing or weak cache control directives",
		"title.web_pragma":                    "Missing Pragma: no-cache header",
		"title.web_ssl_connect":               "SSL/TLS connection failed",
		"title.web_ssl_old_tls":               "Outdated TLS version in use",
		"title.web_ssl_expired":               "SSL certificate has expired",
		"title.web_ssl_expiring":              "SSL certificate expiring soon",
		"title.web_dns_resolve":               "DNS resolution failed",
		"title.web_dns_multi_ip":              "Multiple IP addresses detected",
		"title.web_method":                    "Dangerous HTTP method enabled: %s",
		"title.web_old_nginx":                 "Outdated Nginx version detected",
		"title.web_express":                   "Express.js framework detected",
		"title.web_cors_misconfig":            "CORS misconfiguration detected",
		"title.web_cors_wildcard":             "Overly permissive CORS policy",
		"title.deps_vuln":                     "Vulnerability in %s: %s",

		// Finding descriptions
		"desc.web_no_waf":                     "The application does not appear to be protected by a WAF. This increases exposure to attacks like SQL injection, XSS, and other OWASP Top 10 vulnerabilities. Recommendation: Implement a Web Application Firewall (WAF) such as Cloudflare, AWS WAF, or ModSecurity to filter malicious traffic.",
		"desc.web_missing_hsts":               "Missing HSTS header. This allows SSL stripping attacks.",
		"desc.web_missing_xcto":               "Missing X-Content-Type-Options header. This allows MIME type sniffing attacks.",
		"desc.web_missing_xfo":                "Missing X-Frame-Options header. Application is vulnerable to clickjacking attacks.",
		"desc.web_missing_csp":                "Missing Content-Security-Policy header. This increases XSS and injection attack risks.",
		"desc.web_missing_referrer":           "Missing Referrer-Policy header. This may leak sensitive information via Referer header.",
		"desc.web_missing_permissions":        "Missing Permissions-Policy header. Browser features are not restricted.",
		"desc.web_disclosure_server":          "The Server header reveals Server technology and version: %s. This information can help attackers identify known vulnerabilities.",
		"desc.web_cache_weak":                 "Responses do not include proper cache control headers. Sensitive data may be cached by browsers or proxies.",
		"desc.web_pragma_missing":             "The Pragma header is not set to no-cache, which may allow caching by HTTP/1.0 proxies.",
		"desc.web_ssl_connect":                "Could not establish TLS connection: %v",
		"desc.web_ssl_old":                    "Server supports TLS %d.%d which is deprecated. Minimum should be TLS 1.2",
		"desc.web_ssl_expired":                "Certificate expired on %s",
		"desc.web_ssl_expiring":               "Certificate expires on %s (less than 30 days)",
		"desc.web_dns_fail":                   "Could not resolve %s: %v",
		"desc.web_dns_multi":                  "Domain %s resolves to %d IPs, possible load balancing or CDN",
		"desc.web_method_dangerous":           "The %s method is enabled and may allow unauthorized modifications or information disclosure.",
		"desc.web_nginx_old":                  "Server header reveals Nginx version: %s. Older versions may have known vulnerabilities.",
		"desc.web_express_detected":           "X-Powered-By header reveals Express.js framework. Ensure it's updated to the latest version.",
		"desc.web_cors_cred_wildcard":         "Server allows credentials with wildcard origin (Access-Control-Allow-Origin: * with Allow-Credentials: true). This is a security risk.",
		"desc.web_cors_wildcard":              "Server allows requests from any origin (Access-Control-Allow-Origin: *). This may expose sensitive data to malicious sites.",
	}
}

// === DICCIONARIO ESPAÑOL ===
func esDict() map[string]string {
	return map[string]string{
		// CLI messages
		"msg.scanning_deps":    "🔍 Escaneando dependencias en %s...",
		"msg.scanning_web":     "🔍 Escaneando aplicación web: %s...",
		"msg.report_saved":     "✅ Reporte guardado en %s",
		"msg.warning_osv":      "⚠️  Advertencia: Fallo al consultar OSV para %s: %v",
		"msg.error_invalid_url": "URL inválida: %w",
		"msg.error_fetch":      "No se pudo recuperar %s: %v",
		"msg.error_no_deps":    "no se encontró un archivo de dependencias soportado (package.json o go.mod)",
		"msg.error_url_required": "el flag --url es requerido para escaneo web",
		"msg.error_invalid_type": "tipo de escaneo inválido: %s",

		// Finding titles
		"title.web_no_waf":                    "No se detectó Web Application Firewall",
		"title.web_missing_header":            "Falta encabezado de seguridad: %s",
		"title.web_disclosure":                "Divulgación de información vía encabezado %s",
		"title.web_cache_control":             "Directivas de caché ausentes o débiles",
		"title.web_pragma":                    "Falta encabezado Pragma: no-cache",
		"title.web_ssl_connect":               "Falló la conexión SSL/TLS",
		"title.web_ssl_old_tls":               "Versión de TLS obsoleta en uso",
		"title.web_ssl_expired":               "Certificado SSL expirado",
		"title.web_ssl_expiring":              "Certificado SSL expira pronto",
		"title.web_dns_resolve":               "Falló la resolución DNS",
		"title.web_dns_multi_ip":              "Múltiples direcciones IP detectadas",
		"title.web_method":                    "Método HTTP peligroso habilitado: %s",
		"title.web_old_nginx":                 "Versión obsoleta de Nginx detectada",
		"title.web_express":                   "Framework Express.js detectado",
		"title.web_cors_misconfig":            "Configuración incorrecta de CORS detectada",
		"title.web_cors_wildcard":             "Política CORS demasiado permisiva",
		"title.deps_vuln":                     "Vulnerabilidad en %s: %s",

		// Finding descriptions
		"desc.web_no_waf":                     "La aplicación no parece estar protegida por un WAF. Esto aumenta la exposición a ataques como inyección SQL, XSS y otras vulnerabilidades del OWASP Top 10. Recomendación: Implementar un Web Application Firewall (WAF) como Cloudflare, AWS WAF o ModSecurity para filtrar tráfico malicioso.",
		"desc.web_missing_hsts":               "Falta el encabezado HSTS. Esto permite ataques de SSL stripping.",
		"desc.web_missing_xcto":               "Falta el encabezado X-Content-Type-Options. Esto permite ataques de MIME type sniffing.",
		"desc.web_missing_xfo":                "Falta el encabezado X-Frame-Options. La aplicación es vulnerable a ataques de clickjacking.",
		"desc.web_missing_csp":                "Falta el encabezado Content-Security-Policy. Esto aumenta los riesgos de XSS e inyección.",
		"desc.web_missing_referrer":           "Falta el encabezado Referrer-Policy. Esto puede filtrar información sensible vía el encabezado Referer.",
		"desc.web_missing_permissions":        "Falta el encabezado Permissions-Policy. Las características del navegador no están restringidas.",
		"desc.web_disclosure_server":          "El encabezado Server revela tecnología y versión del servidor: %s. Esta información puede ayudar a atacantes a identificar vulnerabilidades conocidas.",
		"desc.web_cache_weak":                 "Las respuestas no incluyen directivas de caché adecuadas. Datos sensibles pueden ser cacheados por navegadores o proxies.",
		"desc.web_pragma_missing":             "El encabezado Pragma no está configurado como no-cache, lo que puede permitir caché por proxies HTTP/1.0.",
		"desc.web_ssl_connect":                "No se pudo establecer conexión TLS: %v",
		"desc.web_ssl_old":                    "El servidor soporta TLS %d.%d el cual está deprecado. El mínimo debería ser TLS 1.2",
		"desc.web_ssl_expired":                "El certificado expiró el %s",
		"desc.web_ssl_expiring":               "El certificado expira el %s (menos de 30 días)",
		"desc.web_dns_fail":                   "No se pudo resolver %s: %v",
		"desc.web_dns_multi":                  "El dominio %s resuelve a %d IPs, posible balanceo de carga o CDN",
		"desc.web_method_dangerous":           "El método %s está habilitado y puede permitir modificaciones no autorizadas o divulgación de información.",
		"desc.web_nginx_old":                  "El encabezado Server revela versión de Nginx: %s. Versiones antiguas pueden tener vulnerabilidades conocidas.",
		"desc.web_express_detected":           "El encabezado X-Powered-By revela el framework Express.js. Asegúrese de que esté actualizado a la última versión.",
		"desc.web_cors_cred_wildcard":         "El servidor permite credenciales con origen wildcard (Access-Control-Allow-Origin: * con Allow-Credentials: true). Esto es un riesgo de seguridad.",
		"desc.web_cors_wildcard":              "El servidor permite peticiones desde cualquier origen (Access-Control-Allow-Origin: *). Esto puede exponer datos sensibles a sitios maliciosos.",
	}
}
