package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthScanner_BFLA_Detection(t *testing.T) {
	// Mock server: admin=403, user=200 → BFLA
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "Bearer admin-fake" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden"}`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":"user-access"}`))
		}
	}))
	defer server.Close()

	scanner := NewAuthScanner("admin-fake", "user-fake", []string{"/admin"}, 5*time.Second)
	findings, err := scanner.Scan(server.URL)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "AUTH-BFLA-01" {
		t.Errorf("Expected BFLA finding, got %s", findings[0].ID)
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("Expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestAuthScanner_BOLA_Detection(t *testing.T) {
	// Mock server: ambos=200 pero respuestas de tamaño distinto → BOLA
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "Bearer admin-fake" {
			// Respuesta larga (datos sensibles)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":123,"email":"alice@example.com","role":"admin","ssn":"XXX-XX-1234","internal_notes":"secret"}`))
		} else {
			// Respuesta corta (solo datos públicos)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":123,"email":"alice@example.com"}`))
		}
	}))
	defer server.Close()

	scanner := NewAuthScanner("admin-fake", "user-fake", []string{"/api/users/123"}, 5*time.Second)
	findings, err := scanner.Scan(server.URL)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "AUTH-BOLA-01" {
		t.Errorf("Expected BOLA finding, got %s", findings[0].ID)
	}
	if findings[0].Severity != "MEDIUM" {
		t.Errorf("Expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestAuthScanner_NoFinding_WhenSameResponse(t *testing.T) {
	// Mock server: misma respuesta para ambos tokens → sin hallazgos
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	scanner := NewAuthScanner("admin-fake", "user-fake", []string{"/public"}, 5*time.Second)
	findings, err := scanner.Scan(server.URL)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d: %+v", len(findings), findings)
	}
}
