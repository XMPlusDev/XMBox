package cert

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
)

// CertHashes holds the two certificate pin values sing-box's TLS client
// settings consume (https://sing-box.sagernet.org/configuration/shared/tls/):
//
//   - certificate_sha256            -> Certificate (SHA-256 of the cert DER)
//   - certificate_public_key_sha256 -> PublicKey   (SHA-256 of the PKIX public key)
//
// The B64 fields are base64.StdEncoding, exactly the JSON encoding sing-box
// expects inside those list options (Go's []byte JSON encoding); the Hex
// fields are provided for display.
type CertHashes struct {
	Certificate    []byte `json:"-"`
	PublicKey      []byte `json:"-"`
	CertificateB64 string `json:"certificate_sha256"`
	PublicKeyB64   string `json:"certificate_public_key_sha256"`
	CertificateHex string `json:"-"`
	PublicKeyHex   string `json:"-"`
}

// CertHashesOf computes the pin hashes for one certificate.
func CertHashesOf(cert *x509.Certificate) (CertHashes, error) {
	certHash := sha256.Sum256(cert.Raw)
	pubKeyHash, err := publicKeySHA256(cert)
	if err != nil {
		return CertHashes{}, err
	}
	return CertHashes{
		Certificate:    certHash[:],
		PublicKey:      pubKeyHash[:],
		CertificateB64: base64.StdEncoding.EncodeToString(certHash[:]),
		PublicKeyB64:   base64.StdEncoding.EncodeToString(pubKeyHash[:]),
		CertificateHex: hex.EncodeToString(certHash[:]),
		PublicKeyHex:   hex.EncodeToString(pubKeyHash[:]),
	}, nil
}

// CertificateSHA256 returns the SHA-256 hash of the certificate's ASN.1 DER
// bytes — the value sing-box stores in certificate_sha256.
func CertificateSHA256(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

// CertificatePublicKeySHA256 returns the SHA-256 hash of the certificate's
// public key marshaled in PKIX DER form — the value sing-box stores in
// certificate_public_key_sha256. It stays stable across certificate renewals
// that keep the same key pair.
func CertificatePublicKeySHA256(cert *x509.Certificate) ([]byte, error) {
	sum, err := publicKeySHA256(cert)
	if err != nil {
		return nil, err
	}
	return sum[:], nil
}

func publicKeySHA256(cert *x509.Certificate) ([32]byte, error) {
	var zero [32]byte
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return zero, fmt.Errorf("xmboxfunc: marshal public key: %w", err)
	}
	return sha256.Sum256(publicKeyBytes), nil
}

// ParseCertHash decodes a 32-byte certificate hash written either as
// base64.StdEncoding (the sing-box JSON config format) or as hex (either
// case), returning the raw digest.
func ParseCertHash(s string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, fmt.Errorf("xmboxfunc: invalid certificate hash %q (want 32 bytes as base64 or hex)", s)
}

// ParseCertHashList decodes a list of hashes (e.g. a certificate_sha256
// config array); every entry must be valid.
func ParseCertHashList(values []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(values))
	for _, v := range values {
		h, err := ParseCertHash(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	return hashes, nil
}

// VerifyPinnedCertificate checks the leaf certificate against the configured
// pin hashes; it matches if the leaf's DER hash or its public-key hash is in
// the respective list. It is a faithful port of VerifyPinnedCertificate from
// sing-box's common/tls/std_client.go (SagerNet/sing-box, GPL-2.0) and can be
// used directly as tls.Config.VerifyPeerCertificate with empty publicKeyHashes
// (or nil certificateHashes).
func VerifyPinnedCertificate(certificateHashes [][]byte, publicKeyHashes [][]byte, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("xmboxfunc: missing peer certificate")
	}
	certificateHash := sha256.Sum256(rawCerts[0])
	if slices.ContainsFunc(certificateHashes, func(value []byte) bool { return bytes.Equal(value, certificateHash[:]) }) {
		return nil
	}
	leafCertificate, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("xmboxfunc: parse leaf certificate: %w", err)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(leafCertificate.PublicKey)
	if err != nil {
		return fmt.Errorf("xmboxfunc: marshal public key: %w", err)
	}
	publicKeyHash := sha256.Sum256(publicKeyBytes)
	if slices.ContainsFunc(publicKeyHashes, func(value []byte) bool { return bytes.Equal(value, publicKeyHash[:]) }) {
		return nil
	}
	return fmt.Errorf("xmboxfunc: unrecognized peer certificate: sha256 %s, public key sha256 %s",
		base64.StdEncoding.EncodeToString(certificateHash[:]),
		base64.StdEncoding.EncodeToString(publicKeyHash[:]))
}

// PinnedCertificateVerifier adapts VerifyPinnedCertificate to the signature
// of tls.Config.VerifyPeerCertificate:
//
//	cfg.VerifyPeerCertificate = xmboxfunc.PinnedCertificateVerifier(certHashes, nil)
func PinnedCertificateVerifier(certificateHashes [][]byte, publicKeyHashes [][]byte) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return VerifyPinnedCertificate(certificateHashes, publicKeyHashes, rawCerts)
	}
}

// LoadCertificateFile reads the leaf certificate from a PEM (first block,
// e.g. fullchain.pem) or DER certificate file.
func LoadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("xmboxfunc: read certificate file: %w", err)
	}
	if block, _ := pem.Decode(data); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("xmboxfunc: parse certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("xmboxfunc: no certificate found in %s", path)
	}
	return certs[0], nil
}
