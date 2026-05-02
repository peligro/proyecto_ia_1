package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/peligro/proyecto_ia_1/pkg/report"
)

// AuthScanner realiza pruebas gray-box comparando respuestas entre tokens
type AuthScanner struct {
	client     *http.Client
	adminToken string
	userToken  string
	endpoints  []string
}

// NewAuthScanner inicializa el scanner de autorización
func NewAuthScanner(adminToken, userToken string, endpoints []string, timeout time.Duration) *AuthScanner {
	return &AuthScanner{
		client:     &http.Client{Timeout: timeout},
		adminToken: adminToken,
		userToken:  userToken,
		endpoints:  endpoints,
	}
}

// Scan ejecuta las pruebas de autorización en los endpoints proporcionados
func (s *AuthScanner) Scan(baseURL string) ([]report.Finding, error) {
	var findings []report.Finding
	baseURL = strings.TrimRight(baseURL, "/")

	for _, ep := range s.endpoints {
		url := baseURL + "/" + strings.TrimLeft(ep, "/")
		
		adminBody, adminStatus, err := s.fetch(url, s.adminToken)
		if err != nil {
			continue
		}
		
		userBody, userStatus, err := s.fetch(url, s.userToken)
		if err != nil {
			continue
		}

		if finding := s.analyze(url, adminStatus, adminBody, userStatus, userBody); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings, nil
}

func (s *AuthScanner) fetch(url, token string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func (s *AuthScanner) analyze(url string, adminStatus int, adminBody []byte, userStatus int, userBody []byte) *report.Finding {
	// 🔴 BFLA: Usuario accede a endpoint administrativo exitosamente
	if (adminStatus == 401 || adminStatus == 403) && (userStatus == 200 || userStatus == 201) {
		return &report.Finding{
			ID:          "AUTH-BFLA-01",
			Title:       "Broken Function Level Authorization (BFLA)",
			Description: fmt.Sprintf("El token de usuario accedió exitosamente a %s (HTTP %d) mientras el token de admin fue bloqueado (HTTP %d). Indica falta de control de acceso basado en roles.", url, userStatus, adminStatus),
			Severity:    "HIGH",
			Category:    "auth",
			Component:   url,
			Recommendation: "Implementar validación estricta de roles en el middleware de autorización. Verificar que cada endpoint valide scopes/roles antes de procesar la solicitud.",
		}
	}

	// 🟡 BOLA/IDOR: Ambos acceden, pero las respuestas difieren significativamente
	if adminStatus == 200 && (userStatus == 200 || userStatus == 201) {
		adminSize := len(adminBody)
		userSize := len(userBody)
		
		if adminSize > 0 {
			diffRatio := float64(adminSize-userSize) / float64(adminSize)
			if diffRatio > 0.25 || diffRatio < -0.25 {
				return &report.Finding{
					ID:          "AUTH-BOLA-01",
					Title:       "Broken Object Level Authorization (BOLA/IDOR)",
					Description: fmt.Sprintf("El endpoint %s devuelve tamaños de respuesta significativamente distintos para admin (%d bytes) vs usuario (%d bytes). Posible fuga de datos o acceso a recursos de otros usuarios.", url, adminSize, userSize),
					Severity:    "MEDIUM",
					Category:    "auth",
					Component:   url,
					Recommendation: "Validar que el usuario autenticado sea el propietario legítimo del recurso solicitado. Usar UUIDs impredecibles y validar ownership en capa de negocio, no solo en BD.",
				}
			}
		}
	}
	return nil
}