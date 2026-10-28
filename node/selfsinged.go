package node

import (
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"time"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/helper/cert"
)

const (
	selfSignedLeafValidity = 3600 * 24 * time.Hour
)

var safeCertName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func SelfSignedCertFile(tlsSettings *api.TlsSettings, pusher func(string, any) error, client api.API) (certFile string, keyFile string, err error) {
	if !safeCertName.MatchString(tlsSettings.ServerName) {
		return "", "", fmt.Errorf("invalid server name %q for self-signed certificate", tlsSettings.ServerName)
	}

	assetDir := "/etc/XMBox"
	pathBase := filepath.Join(assetDir, tlsSettings.ServerName)

	domains := []string{tlsSettings.ServerName}
	if d := tlsSettings.CertDomainName; d != "" && d != tlsSettings.ServerName {
		domains = append(domains, d)
	}
	
	generatedCert, err := cert.GenerateTLSCert(cert.CertOptions{
		Domains:      domains,
		CommonName:   tlsSettings.ServerName,
		Organization: "XMPlus",
		IsCA:         false,
		Expire:       selfSignedLeafValidity,
	})
	if err != nil {
		return "", "", fmt.Errorf("self-signed cert generate: %w", err)
	}
	if err := generatedCert.Save(pathBase); err != nil {
		return "", "", fmt.Errorf("self-signed cert save: %w", err)
	}
	
	hashes, hErr := generatedCert.Hashes()
	if hErr != nil {
		log.Printf("self-signed hash unavailable: %v", hErr)
		return pathBase + ".crt", pathBase + ".key", nil
	}
	
	if pusher != nil {
		reportPinnedCA(hashes, pusher, client)
	}

	return pathBase + ".crt", pathBase + ".key", nil
}

func reportPinnedCA(hashes cert.CertHashes, pusher func(string, any) error, client api.API) {
	if pusher != nil {
		if pErr := pusher("cert_hashes", map[string]any{"core": "singbox", "certificate_sha256": hashes.CertificateB64, "certificate_public_key_sha256": hashes.PublicKeyB64}); pErr == nil {
			return
		} else {
			log.Printf("cert_hashes push via websocket failed: %v, trying via api", pErr)
		}
	}
	if client != nil {
		if rErr := client.ReportCertHash(&api.CertHash{Core: "singbox", CertSha256: hashes.CertificateB64, CertPublicKeySha256: hashes.PublicKeyB64}); rErr != nil {
			log.Printf("cert_hashes ReportCertHash failed: %v", rErr)
		}
	}	
}
