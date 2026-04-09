package cmd

import (
    "fmt"
	"os"

	"github.com/sagernet/sing-box/common/tls"

	"github.com/spf13/cobra"
)

var (
	echOutputKey    string
	echServerName   string
	echOutputConfig string
	echCmd          = &cobra.Command{
		Use:   "ech",
		Short: "Generate TLS-ECH certificates",
		Long: `Generate TLS-ECH certificates for Encrypted Client Hello.
Examples:
  Generate new ECH keys:              ech
  Set custom server name:             ech --serverName example.com`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := executeECH(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		},
	}
)

func init() {
	echCmd.Flags().StringVar(&echServerName, "serverName", "cloudflare-ech.com", "Server name for ECH config")
	echCmd.PersistentFlags().StringVarP(&echOutputConfig, "config-output", "c", "", "Write ECH config PEM to file instead of stdout")
	echCmd.PersistentFlags().StringVarP(&echOutputKey, "key-output", "k", "", "Write ECH key PEM to file instead of stdout")
	rootCmd.AddCommand(echCmd)
}

func executeECH() error {
	configPem, keyPem, err := tls.ECHKeygenDefault(echServerName)
	if err != nil {
		return fmt.Errorf("generating ECH key pair: %w", err)
	}

	if echOutputConfig != "" {
		if err := os.WriteFile(echOutputConfig, []byte(configPem), 0o644); err != nil {
			return fmt.Errorf("writing ECH config to %s: %w", echOutputConfig, err)
		}
		fmt.Printf("ECH config written to: %s\n", echOutputConfig)
	} else {
		os.Stdout.WriteString(configPem)
	}

	if echOutputKey != "" {
		if err := os.WriteFile(echOutputKey, []byte(keyPem), 0o600); err != nil {
			return fmt.Errorf("writing ECH key to %s: %w", echOutputKey, err)
		}
		fmt.Printf("ECH key written to: %s\n", echOutputKey)
	} else {
		os.Stdout.WriteString(keyPem)
	}

	return nil
}