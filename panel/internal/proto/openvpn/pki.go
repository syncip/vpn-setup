package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Eigene kleine PKI pro Server: eine CA (ECDSA P-256), ein Server-Zertifikat und ein
// Zertifikat pro Zugang. Kein easy-rsa nötig, alles liegt in der Datenbank des Panels.

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n.Add(n, big.NewInt(1))
}

func encodeKey(k *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func encodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newCA erzeugt eine Zertifizierungsstelle (20 Jahre).
func newCA(cn string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return
	}
	keyPEM, err = encodeKey(key)
	return encodeCert(der), keyPEM, err
}

func parseCA(certPEM, keyPEM string) (*x509.Certificate, any, error) {
	cb, _ := pem.Decode([]byte(certPEM))
	kb, _ := pem.Decode([]byte(keyPEM))
	if cb == nil || kb == nil {
		return nil, nil, fmt.Errorf("CA fehlt")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// issue stellt ein Zertifikat aus (10 Jahre). server=true: TLS-Server (für „remote-cert-tls server“
// der Clients: EKU serverAuth, Key Usage digitalSignature+keyAgreement), sonst TLS-Client.
func issue(caCertPEM, caKeyPEM, cn string, server bool) (certPEM, keyPEM string, err error) {
	ca, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return
	}
	keyPEM, err = encodeKey(key)
	return encodeCert(der), keyPEM, err
}

// signedBy: Zertifikat gültig und von dieser CA ausgestellt?
func signedBy(certPEM, caPEM string) bool {
	cb, _ := pem.Decode([]byte(certPEM))
	ab, _ := pem.Decode([]byte(caPEM))
	if cb == nil || ab == nil {
		return false
	}
	c, err1 := x509.ParseCertificate(cb.Bytes)
	ca, err2 := x509.ParseCertificate(ab.Bytes)
	if err1 != nil || err2 != nil {
		return false
	}
	return c.CheckSignatureFrom(ca) == nil && time.Now().Before(c.NotAfter)
}

func notAfter(certPEM string) time.Time {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		return time.Time{}
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}
	}
	return c.NotAfter
}

// tlsCryptKey: statischer Schlüssel für tls-crypt (2048 Bit, OpenVPN-Format). Verschlüsselt und
// authentifiziert schon den TLS-Handshake – ohne Schlüssel antwortet der Server gar nicht.
func tlsCryptKey() string {
	b := make([]byte, 256)
	_, _ = rand.Read(b)
	var s strings.Builder
	s.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(b); i += 16 {
		s.WriteString(hex.EncodeToString(b[i:i+16]) + "\n")
	}
	s.WriteString("-----END OpenVPN Static key V1-----\n")
	return s.String()
}
