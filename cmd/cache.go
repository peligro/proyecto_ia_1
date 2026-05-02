package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/peligro/proyecto_ia_1/pkg/ai"
	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage AI response cache",
	Long:  `Commands to view, clear, or configure the AI response cache`,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all cached AI responses",
	RunE: func(cmd *cobra.Command, args []string) error {
		cacheDir := filepath.Join(os.Getenv("HOME"), ".ai-audit", "cache")
		if customDir, _ := cmd.Flags().GetString("dir"); customDir != "" {
			cacheDir = customDir
		}
		
		cache := ai.NewCache(cacheDir, 0, true)
		if err := cache.Clear(); err != nil {
			return fmt.Errorf("failed to clear cache: %w", err)
		}
		
		fmt.Printf("✅ Cache cleared: %s\n", cacheDir)
		return nil
	},
}

var cacheStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show cache statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		cacheDir := filepath.Join(os.Getenv("HOME"), ".ai-audit", "cache")
		if customDir, _ := cmd.Flags().GetString("dir"); customDir != "" {
			cacheDir = customDir
		}
		
		cache := ai.NewCache(cacheDir, 0, true)
		count, size, err := cache.Stats()
		if err != nil {
			return fmt.Errorf("failed to read cache: %w", err)
		}
		
		fmt.Printf("📊 AI Cache Statistics\n")
		fmt.Printf("   Directory: %s\n", cacheDir)
		fmt.Printf("   Entries: %d\n", count)
		fmt.Printf("   Size: %.2f KB\n", float64(size)/1024)
		fmt.Printf("   TTL: 24h (default)\n")
		return nil
	},
}

func init() {
	cacheClearCmd.Flags().String("dir", "", "Custom cache directory")
	cacheStatsCmd.Flags().String("dir", "", "Custom cache directory")
	
	cacheCmd.AddCommand(cacheClearCmd)
	cacheCmd.AddCommand(cacheStatsCmd)
	
	rootCmd.AddCommand(cacheCmd)
}
