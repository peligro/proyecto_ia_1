package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/report"
)

type WebScanner struct {
	Client      *http.Client
	Timeout     time.Duration
	UserAgent   string
	Target      string
	ParsedURL   *url.URL
}

func NewWebScanner(timeout time.Duration) *WebScanner {
	return &WebScanner{
		Timeout: timeout,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ai-audit-cli",
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (ws *WebScanner) Scan(target string) ([]report.Finding, error) {
	var findings []report.Finding

	// Parse URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	ws.Target = target
	ws.ParsedURL = parsedURL

	// 1. DNS Discovery
	findings = append(findings, ws.dnsDiscovery()...)

	// 2. WAF Detection
	findings = append(findings, ws.detectWAF()...)

	// 3. SSL/TLS Analysis
	if parsedURL.Scheme == "https" {
		findings = append(findings, ws.analyzeSSL()...)
	}

	// 4. Fetch main page
	resp, err := ws.fetchPage(target)
	if err != nil {
		findings = append(findings, report.Finding{
			ID:          "WEB-NO-WAF",
			Title:       "No Web Application Firewall detected",
			Description: "The application does not appear to be protected by a WAF. This increases exposure to attacks like SQL injection, XSS, and other OWASP Top 10 vulnerabilities. Recommendation: Implement a WAF such as Cloudflare, AWS WAF, or ModSecurity.",
			Severity:    report.High,
			Category:    "web",
			FoundAt:     time.Now(),
		})
		return findings, nil
	}
	defer resp.Body.Close()

	// 5. Security Headers
	findings = append(findings, ws.checkSecurityHeaders(resp.Header)...)

	// 6. Information Disclosure
	findings = append(findings, ws.checkInfoDisclosure(resp.Header)...)

	// 7. HTTP Methods
	findings = append(findings, ws.checkHTTPMethods(target)...)

	// 8. Cache Control
	findings = append(findings, ws.checkCacheControl(resp.Header)...)

	// 9. Technology Detection
	findings = append(findings, ws.detectTechnologies(resp.Header)...)

	// 10. CORS Check
	findings = append(findings, ws.checkCORS(resp.Header)...)

	return findings, nil
}

func (ws *WebScanner) fetchPage(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ws.UserAgent)
	return ws.Client.Do(req)
}

func (ws *WebScanner) dnsDiscovery() []report.Finding {
	var findings []report.Finding
	
	host := ws.ParsedURL.Hostname()
	
	// A record lookup
	ips, err := net.LookupIP(host)
	if err != nil {
		findings = append(findings, report.Finding{
			ID:          "WEB-DNS-RESOLVE",
			Title:       "DNS resolution failed",
			Description: fmt.Sprintf("Could not resolve %s: %v", host, err),
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	} else {
		// Info disclosure: multiple IPs
		if len(ips) > 3 {
			findings = append(findings, report.Finding{
				ID:          "WEB-DNS-MULTI-IP",
				Title:       "Multiple IP addresses detected",
				Description: fmt.Sprintf("Domain %s resolves to %d IPs, possible load balancing or CDN", host, len(ips)),
				Severity:    report.Low,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
	}

	return findings
}

func (ws *WebScanner) detectWAF() []report.Finding {
	var findings []report.Finding
	
	// Common WAF detection headers
	wafHeaders := []string{
		"X-Sucuri-ID",
		"X-Sucuri-Cache",
		"X-Cloudflare-Trace",
		"CF-RAY",
		"X-Akamai-Transformed",
		"X-AWS-Lambda",
		"Server",
	}

	req, _ := http.NewRequest("GET", ws.Target, nil)
	req.Header.Set("User-Agent", ws.UserAgent)
	resp, err := ws.Client.Do(req)
	
	if err == nil {
		defer resp.Body.Close()
		
		hasWAF := false
		for _, header := range wafHeaders {
			if val := resp.Header.Get(header); val != "" {
				if strings.Contains(strings.ToLower(val), "cloudflare") ||
				   strings.Contains(strings.ToLower(val), "sucuri") ||
				   strings.Contains(strings.ToLower(val), "akamai") {
					hasWAF = true
					break
				}
			}
		}

		if !hasWAF {
			findings = append(findings, report.Finding{
				ID:          "WEB-NO-WAF",
				Title:       "No Web Application Firewall detected",
				Description: "The application does not appear to be protected by a WAF. This increases exposure to attacks like SQL injection, XSS, and other OWASP Top 10 vulnerabilities. Recommendation: Implement a Web Application Firewall (WAF) such as Cloudflare, AWS WAF, or ModSecurity to filter malicious traffic.",
				Severity:    report.High,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
	}

	return findings
}

func (ws *WebScanner) analyzeSSL() []report.Finding {
	var findings []report.Finding
	
	host := ws.ParsedURL.Hostname()
	port := ws.ParsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Check TLS configuration
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	
	if err != nil {
		findings = append(findings, report.Finding{
			ID:          "WEB-SSL-CONNECT",
			Title:       "SSL/TLS connection failed",
			Description: fmt.Sprintf("Could not establish TLS connection: %v", err),
			Severity:    report.High,
			Category:    "web",
			FoundAt:     time.Now(),
		})
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()
	
	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, report.Finding{
			ID:          "WEB-SSL-OLD-TLS",
			Title:       "Outdated TLS version in use",
			Description: fmt.Sprintf("Server supports TLS %d.%d which is deprecated. Minimum should be TLS 1.2", state.Version>>8, state.Version&0xff),
			Severity:    report.High,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}

	// Check certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		
		// Check expiration
		if cert.NotAfter.Before(time.Now()) {
			findings = append(findings, report.Finding{
				ID:          "WEB-SSL-EXPIRED",
				Title:       "SSL certificate has expired",
				Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
				Severity:    report.Critical,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
		
		// Check if expiring soon
		if cert.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
			findings = append(findings, report.Finding{
				ID:          "WEB-SSL-EXPIRING",
				Title:       "SSL certificate expiring soon",
				Description: fmt.Sprintf("Certificate expires on %s (less than 30 days)", cert.NotAfter.Format("2006-01-02")),
				Severity:    report.Medium,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
	}

	return findings
}

func (ws *WebScanner) checkSecurityHeaders(headers http.Header) []report.Finding {
	var findings []report.Finding

	requiredHeaders := map[string]struct {
		Severity    report.Severity
		Description string
	}{
		"Strict-Transport-Security": {
			Severity:    report.High,
			Description: "Missing HSTS header. This allows SSL stripping attacks.",
		},
		"X-Content-Type-Options": {
			Severity:    report.Medium,
			Description: "Missing X-Content-Type-Options header. This allows MIME type sniffing attacks.",
		},
		"X-Frame-Options": {
			Severity:    report.Medium,
			Description: "Missing X-Frame-Options header. Application is vulnerable to clickjacking attacks.",
		},
		"Content-Security-Policy": {
			Severity:    report.Medium,
			Description: "Missing Content-Security-Policy header. This increases XSS and injection attack risks.",
		},
		"Referrer-Policy": {
			Severity:    report.Low,
			Description: "Missing Referrer-Policy header. This may leak sensitive information via Referer header.",
		},
		"Permissions-Policy": {
			Severity:    report.Low,
			Description: "Missing Permissions-Policy header. Browser features are not restricted.",
		},
	}

	for header, info := range requiredHeaders {
		if values := headers.Values(header); len(values) == 0 {
			findings = append(findings, report.Finding{
				ID:          fmt.Sprintf("WEB-MISSING-%s", strings.ReplaceAll(header, "-", "")),
				Title:       fmt.Sprintf("Missing security header: %s", header),
				Description: info.Description,
				Severity:    info.Severity,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
	}

	return findings
}

func (ws *WebScanner) checkInfoDisclosure(headers http.Header) []report.Finding {
	var findings []report.Finding

	disclosureHeaders := map[string]string{
		"Server":           "Server technology and version",
		"X-Powered-By":     "Backend framework/language",
		"X-AspNet-Version": "ASP.NET version",
		"X-AspNetMvc-Version": "ASP.NET MVC version",
	}

	for header, description := range disclosureHeaders {
		if values := headers.Values(header); len(values) > 0 {
			findings = append(findings, report.Finding{
				ID:          fmt.Sprintf("WEB-DISCLOSURE-%s", strings.ReplaceAll(header, "-", "")),
				Title:       fmt.Sprintf("Information disclosure via %s header", header),
				Description: fmt.Sprintf("The %s header reveals %s: %s. This information can help attackers identify known vulnerabilities.", header, description, values[0]),
				Severity:    report.Low,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
	}

	return findings
}

func (ws *WebScanner) checkHTTPMethods(target string) []report.Finding {
	var findings []report.Finding

	// Check OPTIONS method
	req, _ := http.NewRequest("OPTIONS", target, nil)
	req.Header.Set("User-Agent", ws.UserAgent)
	resp, err := ws.Client.Do(req)
	
	if err == nil {
		defer resp.Body.Close()
		
		allowedMethods := resp.Header.Get("Allow")
		if allowedMethods != "" {
			methods := strings.Split(allowedMethods, ",")
			dangerousMethods := []string{"PUT", "DELETE", "TRACE", "CONNECT"}
			
			for _, method := range methods {
				method = strings.TrimSpace(method)
				for _, dangerous := range dangerousMethods {
					if method == dangerous {
						findings = append(findings, report.Finding{
							ID:          fmt.Sprintf("WEB-METHOD-%s", method),
							Title:       fmt.Sprintf("Dangerous HTTP method enabled: %s", method),
							Description: fmt.Sprintf("The %s method is enabled and may allow unauthorized modifications or information disclosure.", method),
							Severity:    report.Medium,
							Category:    "web",
							FoundAt:     time.Now(),
						})
					}
				}
			}
		}
	}

	return findings
}

func (ws *WebScanner) checkCacheControl(headers http.Header) []report.Finding {
	var findings []report.Finding

	cacheControl := headers.Get("Cache-Control")
	pragma := headers.Get("Pragma")

	// Check if sensitive responses are cacheable
	if cacheControl == "" || (!strings.Contains(cacheControl, "no-store") && 
		!strings.Contains(cacheControl, "no-cache") &&
		!strings.Contains(cacheControl, "private")) {
		
		findings = append(findings, report.Finding{
			ID:          "WEB-CACHE-CONTROL",
			Title:       "Missing or weak cache control directives",
			Description: "Responses do not include proper cache control headers. Sensitive data may be cached by browsers or proxies.",
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}

	if pragma == "" || !strings.Contains(pragma, "no-cache") {
		findings = append(findings, report.Finding{
			ID:          "WEB-PRAGMA",
			Title:       "Missing Pragma: no-cache header",
			Description: "The Pragma header is not set to no-cache, which may allow caching by HTTP/1.0 proxies.",
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}

	return findings
}

func (ws *WebScanner) detectTechnologies(headers http.Header) []report.Finding {
	var findings []report.Finding

	// Check for specific technologies
	server := headers.Get("Server")
	poweredBy := headers.Get("X-Powered-By")

	// Check for outdated technologies
	if strings.Contains(strings.ToLower(server), "nginx") {
		if strings.Contains(server, "/1.") || strings.Contains(server, "/0.") {
			findings = append(findings, report.Finding{
				ID:          "WEB-OLD-NGINX",
				Title:       "Outdated Nginx version detected",
				Description: fmt.Sprintf("Server header reveals Nginx version: %s. Older versions may have known vulnerabilities.", server),
				Severity:    report.Medium,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
	}

	if strings.Contains(strings.ToLower(poweredBy), "express") {
		findings = append(findings, report.Finding{
			ID:          "WEB-EXPRESS",
			Title:       "Express.js framework detected",
			Description: "X-Powered-By header reveals Express.js framework. Ensure it's updated to the latest version.",
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}

	return findings
}

func (ws *WebScanner) checkCORS(headers http.Header) []report.Finding {
	var findings []report.Finding

	accessControlAllowOrigin := headers.Get("Access-Control-Allow-Origin")
	accessControlAllowCredentials := headers.Get("Access-Control-Allow-Credentials")

	if accessControlAllowOrigin == "*" && accessControlAllowCredentials == "true" {
		findings = append(findings, report.Finding{
			ID:          "WEB-CORS-MISCONFIG",
			Title:       "CORS misconfiguration detected",
			Description: "Server allows credentials with wildcard origin (Access-Control-Allow-Origin: * with Allow-Credentials: true). This is a security risk.",
			Severity:    report.High,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	} else if accessControlAllowOrigin == "*" {
		findings = append(findings, report.Finding{
			ID:          "WEB-CORS-WILDCARD",
			Title:       "Overly permissive CORS policy",
			Description: "Server allows requests from any origin (Access-Control-Allow-Origin: *). This may expose sensitive data to malicious sites.",
			Severity:    report.Medium,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}

	return findings
}