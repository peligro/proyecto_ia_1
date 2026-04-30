package cmd

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ai-audit",
	Short: "AI-powered security audit CLI",
	Long:  `A security scanner for dependencies, web apps, and AI integrations`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}