package main

import "github.com/peligro/proyecto_ia_1/cmd"

// Variables inyectadas por GoReleaser vía ldflags
// No las inicialices aquí, GoReleaser las sobrescribirá en build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Pasar las variables a cmd para que cobra las use
	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}