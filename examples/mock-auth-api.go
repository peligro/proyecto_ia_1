
// examples/mock-auth-api.go
// Ejecutar: go run examples/mock-auth-api.go
package main

import (
	"net/http"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	
	// Simular BFLA: endpoint /admin solo para admin
	if strings.Contains(r.URL.Path, "/admin") {
		if strings.Contains(token, "admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data": "ADMIN_SECRET_123", "users": ["alice", "bob"]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "forbidden"}`))
		return
	}
	
	// Simular BOLA: /api/users/123 devuelve datos distintos según token
	if strings.Contains(r.URL.Path, "/api/users/") {
		if strings.Contains(token, "admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 123, "email": "alice@example.com", "role": "admin", "ssn": "XXX-XX-1234"}`))
			return
		}
		// Usuario normal ve menos campos (pero aún ve datos de otro usuario → BOLA)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 123, "email": "alice@example.com"}`))
		return
	}
	
	// Default: mismo response para todos
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
}

func main() {
	http.HandleFunc("/", handler)
	println("🚀 Mock API running on http://localhost:8888")
	println("   Admin token: 'Bearer admin-fake'")
	println("   User token:  'Bearer user-fake'")
	http.ListenAndServe(":8888", nil)
}