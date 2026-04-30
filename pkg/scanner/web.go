package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/i18n"
	"github.com/peligro/proyecto_ia_1/pkg/report"
)

type WebScanner struct {
	Client    *http.Client
	Timeout   time.Duration
	UserAgent string
	Target    string
	ParsedURL *url.URL
}

func NewWebScanner(timeout time.Duration) *WebScanner {
	return &WebScanner{
		Timeout:   timeout,
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

	parsedURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf(i18n.T.Get("msg.error_invalid_url"), err)
	}
	ws.Target = target
	ws.ParsedURL = parsedURL

	findings = append(findings, ws.dnsDiscovery()...)
	findings = append(findings, ws.detectWAF()...)

	if parsedURL.Scheme == "https" {
		findings = append(findings, ws.analyzeSSL()...)
	}

	resp, err := ws.fetchPage(target)
	if err != nil {
		findings = append(findings, report.Finding{
			ID:          "WEB-FETCH-ERROR",
			Title:       i18n.T.Get("title.web_fetch_error"),
			Description: fmt.Sprintf(i18n.T.Get("desc.web_fetch_error"), target, err),
			Severity:    report.High,
			Category:    "web",
			FoundAt:     time.Now(),
		})
		return findings, nil
	}
	defer resp.Body.Close()

	findings = append(findings, ws.checkSecurityHeaders(resp.Header)...)
	findings = append(findings, ws.checkInfoDisclosure(resp.Header)...)
	findings = append(findings, ws.checkHTTPMethods(target)...)
	findings = append(findings, ws.checkCacheControl(resp.Header)...)
	findings = append(findings, ws.detectTechnologies(resp.Header)...)
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

	ips, err := net.LookupIP(host)
	if err != nil {
		findings = append(findings, report.Finding{
			ID:          "WEB-DNS-RESOLVE",
			Title:       i18n.T.Get("title.web_dns_resolve"),
			Description: fmt.Sprintf(i18n.T.Get("desc.web_dns_fail"), host, err),
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	} else if len(ips) > 3 {
		findings = append(findings, report.Finding{
			ID:          "WEB-DNS-MULTI-IP",
			Title:       i18n.T.Get("title.web_dns_multi_ip"),
			Description: fmt.Sprintf(i18n.T.Get("desc.web_dns_multi"), host, len(ips)),
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}
	return findings
}

func (ws *WebScanner) detectWAF() []report.Finding {
	var findings []report.Finding

	wafHeaders := []string{
		"X-Sucuri-ID", "X-Sucuri-Cache", "X-Cloudflare-Trace",
		"CF-RAY", "X-Akamai-Transformed", "X-AWS-Lambda", "Server",
	}

	req, _ := http.NewRequest("GET", ws.Target, nil)
	req.Header.Set("User-Agent", ws.UserAgent)
	resp, err := ws.Client.Do(req)

	if err == nil {
		defer resp.Body.Close()
		hasWAF := false
		for _, header := range wafHeaders {
			if val := resp.Header.Get(header); val != "" {
				lower := strings.ToLower(val)
				if strings.Contains(lower, "cloudflare") ||
					strings.Contains(lower, "sucuri") ||
					strings.Contains(lower, "akamai") {
					hasWAF = true
					break
				}
			}
		}

		if !hasWAF {
			findings = append(findings, report.Finding{
				ID:             "ARQ-A1",
				Title:          i18n.T.Get("title.web_no_waf"),
				Description:    i18n.T.Get("desc.web_no_waf"),
				Severity:       report.High,
				Category:       "architecture",
				Component:      ws.Target,
				Recommendation: i18n.T.Get("rec.web_no_waf"),
				FoundAt:        time.Now(),
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

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		findings = append(findings, report.Finding{
			ID:          "WEB-SSL-CONNECT",
			Title:       i18n.T.Get("title.web_ssl_connect"),
			Description: fmt.Sprintf(i18n.T.Get("desc.web_ssl_connect"), err),
			Severity:    report.High,
			Category:    "web",
			FoundAt:     time.Now(),
		})
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if state.Version < tls.VersionTLS12 {
		major := state.Version >> 8
		minor := state.Version & 0xff
		findings = append(findings, report.Finding{
			ID:          "WEB-SSL-OLD-TLS",
			Title:       i18n.T.Get("title.web_ssl_old_tls"),
			Description: fmt.Sprintf(i18n.T.Get("desc.web_ssl_old"), major, minor),
			Severity:    report.High,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if cert.NotAfter.Before(time.Now()) {
			findings = append(findings, report.Finding{
				ID:          "WEB-SSL-EXPIRED",
				Title:       i18n.T.Get("title.web_ssl_expired"),
				Description: fmt.Sprintf(i18n.T.Get("desc.web_ssl_expired"), cert.NotAfter.Format("2006-01-02")),
				Severity:    report.Critical,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		} else if cert.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
			findings = append(findings, report.Finding{
				ID:          "WEB-SSL-EXPIRING",
				Title:       i18n.T.Get("title.web_ssl_expiring"),
				Description: fmt.Sprintf(i18n.T.Get("desc.web_ssl_expiring"), cert.NotAfter.Format("2006-01-02")),
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
		Key         string
		Severity    report.Severity
		DescKey     string
		RecommendKey string
	}{
		"Strict-Transport-Security": {
			Key: "HSTS", Severity: report.High,
			DescKey: "desc.web_missing_hsts", RecommendKey: "rec.web_missing_hsts",
		},
		"X-Content-Type-Options": {
			Key: "X-Content-Type-Options", Severity: report.Medium,
			DescKey: "desc.web_missing_xcto", RecommendKey: "rec.web_missing_xcto",
		},
		"X-Frame-Options": {
			Key: "X-Frame-Options", Severity: report.Medium,
			DescKey: "desc.web_missing_xfo", RecommendKey: "rec.web_missing_xfo",
		},
		"Content-Security-Policy": {
			Key: "CSP", Severity: report.Medium,
			DescKey: "desc.web_missing_csp", RecommendKey: "rec.web_missing_csp",
		},
		"Referrer-Policy": {
			Key: "Referrer-Policy", Severity: report.Low,
			DescKey: "desc.web_missing_referrer", RecommendKey: "rec.web_missing_referrer",
		},
		"Permissions-Policy": {
			Key: "Permissions-Policy", Severity: report.Low,
			DescKey: "desc.web_missing_permissions", RecommendKey: "rec.web_missing_permissions",
		},
	}

	for header, info := range requiredHeaders {
		if values := headers.Values(header); len(values) == 0 {
			findings = append(findings, report.Finding{
				ID:             fmt.Sprintf("API-M1-%s", strings.ReplaceAll(header, "-", "")),
				Title:          fmt.Sprintf(i18n.T.Get("title.web_missing_header"), info.Key),
				Description:    i18n.T.Get(info.DescKey),
				Severity:       info.Severity,
				Category:       "web",
				Component:      ws.Target,
				Recommendation: i18n.T.Get(info.RecommendKey),
				FoundAt:        time.Now(),
			})
		}
	}
	return findings
}

func (ws *WebScanner) checkInfoDisclosure(headers http.Header) []report.Finding {
	var findings []report.Finding

	disclosureHeaders := map[string]string{
		"Server":       "desc.web_disclosure_server",
		"X-Powered-By": "desc.web_disclosure_poweredby",
	}

	for header, descKey := range disclosureHeaders {
		if values := headers.Values(header); len(values) > 0 {
			findings = append(findings, report.Finding{
				ID:          fmt.Sprintf("WEB-B3-%s", strings.ReplaceAll(header, "-", "")),
				Title:       fmt.Sprintf(i18n.T.Get("title.web_disclosure"), header),
				Description: fmt.Sprintf(i18n.T.Get(descKey), values[0]),
				Severity:    report.Low,
				Category:    "web",
				Component:   ws.Target,
				FoundAt:     time.Now(),
			})
		}
	}
	return findings
}

func (ws *WebScanner) checkHTTPMethods(target string) []report.Finding {
	var findings []report.Finding

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
							ID:             fmt.Sprintf("API-B1-%s", method),
							Title:          fmt.Sprintf(i18n.T.Get("title.web_method"), method),
							Description:    i18n.T.Get("desc.web_method_dangerous"),
							Severity:       report.Medium,
							Category:       "api",
							Component:      ws.Target,
							Recommendation: i18n.T.Get("rec.web_method"),
							FoundAt:        time.Now(),
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

	if cacheControl == "" || (!strings.Contains(cacheControl, "no-store") &&
		!strings.Contains(cacheControl, "no-cache") &&
		!strings.Contains(cacheControl, "private")) {

		findings = append(findings, report.Finding{
			ID:             "API-B2",
			Title:          i18n.T.Get("title.web_cache_control"),
			Description:    i18n.T.Get("desc.web_cache_weak"),
			Severity:       report.Low,
			Category:       "api",
			Component:      ws.Target,
			Recommendation: i18n.T.Get("rec.web_cache_control"),
			FoundAt:        time.Now(),
		})
	}

	if pragma == "" || !strings.Contains(pragma, "no-cache") {
		findings = append(findings, report.Finding{
			ID:          "WEB-PRAGMA",
			Title:       i18n.T.Get("title.web_pragma"),
			Description: i18n.T.Get("desc.web_pragma_missing"),
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}
	return findings
}

func (ws *WebScanner) detectTechnologies(headers http.Header) []report.Finding {
	var findings []report.Finding

	server := headers.Get("Server")
	poweredBy := headers.Get("X-Powered-By")

	if strings.Contains(strings.ToLower(server), "nginx") {
		if strings.Contains(server, "/1.") || strings.Contains(server, "/0.") {
			findings = append(findings, report.Finding{
				ID:          "WEB-OLD-NGINX",
				Title:       i18n.T.Get("title.web_old_nginx"),
				Description: fmt.Sprintf(i18n.T.Get("desc.web_nginx_old"), server),
				Severity:    report.Medium,
				Category:    "web",
				FoundAt:     time.Now(),
			})
		}
	}

	if strings.Contains(strings.ToLower(poweredBy), "express") {
		findings = append(findings, report.Finding{
			ID:          "WEB-EXPRESS",
			Title:       i18n.T.Get("title.web_express"),
			Description: i18n.T.Get("desc.web_express_detected"),
			Severity:    report.Low,
			Category:    "web",
			FoundAt:     time.Now(),
		})
	}
	return findings
}

func (ws *WebScanner) checkCORS(headers http.Header) []report.Finding {
	var findings []report.Finding

	allowOrigin := headers.Get("Access-Control-Allow-Origin")
	allowCreds := headers.Get("Access-Control-Allow-Credentials")

	if allowOrigin == "*" && allowCreds == "true" {
		findings = append(findings, report.Finding{
			ID:             "API-C3-CORS-MISCONFIG",
			Title:          i18n.T.Get("title.web_cors_misconfig"),
			Description:    i18n.T.Get("desc.web_cors_cred_wildcard"),
			Severity:       report.High,
			Category:       "api",
			Component:      ws.Target,
			Recommendation: i18n.T.Get("rec.web_cors"),
			FoundAt:        time.Now(),
		})
	} else if allowOrigin == "*" {
		findings = append(findings, report.Finding{
			ID:             "API-C3-CORS-WILDCARD",
			Title:          i18n.T.Get("title.web_cors_wildcard"),
			Description:    i18n.T.Get("desc.web_cors_wildcard"),
			Severity:       report.Medium,
			Category:       "api",
			Component:      ws.Target,
			Recommendation: i18n.T.Get("rec.web_cors"),
			FoundAt:        time.Now(),
		})
	}
	return findings
}