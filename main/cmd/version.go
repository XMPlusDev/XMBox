package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	version  = `XMBox v2604120`
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Current version of XMBox",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("%s\n", version)
}