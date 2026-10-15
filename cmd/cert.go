package cmd

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	certHashFile       string
	certHashRemoteAddr string
	certHashServerName string
	certHashCmd        = &cobra.Command{
		Use:   "cert-hash",
		Short: "Generate SHA-256 pins for a certificate (TLS certificate pinning)",
		Long: `Generate SHA-256 pins for a certificate, in the base64 format sing-box expects.

Use certificate for certificate_sha256 / client_certificate_sha256
(pins the whole DER-encoded certificate) and public-key for
certificate_public_key_sha256 / client_certificate_public_key_sha256
(pins the PKIX-marshaled public key).

Examples:
  From PEM file:   cert-hash -f "cert.pem"
  Remote server:   cert-hash --remote example.com:443 --server-name example.com`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := executeCertHash(); err != nil {
				fmt.Println(err)
			}
		},
	}
)

func init() {
	certHashCmd.Flags().StringVarP(&certHashFile, "file", "f", "", "PEM certificate file (certificate or chain; the leaf is pinned)")
	certHashCmd.Flags().StringVar(&certHashRemoteAddr, "remote", "", "Fetch the certificate chain from a remote TLS server (host:port)")
	certHashCmd.Flags().StringVar(&certHashServerName, "server-name", "", "Server name (SNI) for --remote; defaults to the remote host")
	rootCmd.AddCommand(certHashCmd)
}

func executeCertHash() error {
	cert, err := loadPinCertificate()
	if err != nil {
		return err
	}

	certHash := sha256.Sum256(cert.Raw)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}
	publicKeyHash := sha256.Sum256(publicKeyDER)

	fmt.Printf("Certificate SHA-256 (certificate_sha256 / client_certificate_sha256):\n%v\n\n",
		base64.StdEncoding.EncodeToString(certHash[:]))
	fmt.Printf("Public key SHA-256 (certificate_public_key_sha256 / client_certificate_public_key_sha256):\n%v\n",
		base64.StdEncoding.EncodeToString(publicKeyHash[:]))
	return nil
}

// loadPinCertificate returns the leaf certificate to pin, either from the PEM
// file (--file, first CERTIFICATE block) or fetched from a remote server.
func loadPinCertificate() (*x509.Certificate, error) {
	if certHashFile != "" && certHashRemoteAddr != "" {
		return nil, fmt.Errorf("use only one of --file or --remote")
	}
	switch {
	case certHashFile != "":
		raw, err := os.ReadFile(certHashFile)
		if err != nil {
			return nil, fmt.Errorf("reading certificate file: %w", err)
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("no CERTIFICATE PEM block found in %s", certHashFile)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		return cert, nil
	case certHashRemoteAddr != "":
		return fetchRemoteCertificate(certHashRemoteAddr, certHashServerName)
	default:
		return nil, fmt.Errorf("provide a certificate source: --file or --remote")
	}
}

// fetchRemoteCertificate dials addr over TCP and returns the peer's leaf
// certificate without verifying the chain, so pins can be bootstrapped from
// a server whose trust is being established.
func fetchRemoteCertificate(addr, serverName string) (*x509.Certificate, error) {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else {
		addr = net.JoinHostPort(addr, "443")
	}
	if serverName == "" {
		serverName = host
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: serverName},
	)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", addr, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented by %s", addr)
	}
	return state.PeerCertificates[0], nil
}
