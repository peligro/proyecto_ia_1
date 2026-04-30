package ai

import "fmt"
// Prompts especializados para análisis de seguridad

// ExplainVulnerability genera un prompt para explicar una vulnerabilidad
func ExplainVulnerability(title, severity, description, category string) string {
	return fmt.Sprintf(`Como experto en ciberseguridad, explica esta vulnerabilidad de forma clara:

VULNERABILIDAD: %s
SEVERIDAD: %s
DESCRIPCIÓN: %s
CATEGORÍA: %s

Proporciona:
1. Explicación simple del riesgo (2-3 líneas, lenguaje accesible)
2. Impacto potencial en el negocio si no se corrige
3. Solución técnica específica con ejemplos de código o configuración
4. Prioridad: inmediata / corto plazo (1-2 semanas) / mediano plazo (1-3 meses)

Formato:
- Usa markdown ligero
- Sé conciso pero completo
- Incluye ejemplos prácticos cuando aplique`,
		title, severity, description, category)
}

// SuggestFix genera un prompt para sugerir fixes de código
func SuggestFix(vulnTitle, techStack, evidence string) string {
	return fmt.Sprintf(`Como desarrollador senior experto en seguridad, sugiere un fix concreto:

VULNERABILIDAD: %s
TECH STACK: %s
EVIDENCIA: %s

Proporciona:
1. Código específico para corregir el problema
2. Explicación breve de por qué funciona
3. Cómo verificar que el fix es efectivo
4. Posibles efectos secundarios a considerar

Formato:
- Devuelve solo código y explicación, sin preámbulos
- Usa bloques de código con lenguaje especificado`,
		vulnTitle, techStack, evidence)
}

// ExecutiveSummary genera un prompt para resumen ejecutivo
func ExecutiveSummary(target string, total, critical, high, medium, low int) string {
	return fmt.Sprintf(`Como consultor de ciberseguridad senior, genera un resumen ejecutivo:

OBJETIVO: %s
HALLAZGOS: %d total (Críticos: %d, Altos: %d, Medios: %d, Bajos: %d)

Proporciona:
1. Párrafo ejecutivo (3-4 líneas) para gerencia no técnica
2. Top 3 prioridades de remediación con justificación de negocio
3. Estimación de esfuerzo: bajo/medio/alto para corregir críticos/altos
4. Recomendación: ¿Es seguro poner en producción? ¿Mitigaciones temporales?

Formato:
- Lenguaje claro, sin jerga técnica excesiva
- Enfocado en impacto de negocio
- Máximo 200 palabras`,
		target, total, critical, high, medium, low)
}
