package collect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/cyd01/tlsclient/pkg/client"
	"github.com/cyd01/tlsclient/pkg/types"
)

// CollectCertificates extrait toute la chaîne TLS.
func CollectCertificates(c *client.Connection) error {

	state := c.TLSState

	for i, cert := range state.PeerCertificates {

		info := certToInfo(cert)

		info.IsLeaf = i == 0

		c.Report.Certificates = append(c.Report.Certificates, info)
	}

	return nil
}

func certToInfo(cert *x509.Certificate) types.CertificateInfo {

	return types.CertificateInfo{
		Subject: cert.Subject.String(),
		Issuer:  cert.Issuer.String(),

		SerialNumber: cert.SerialNumber.String(),

		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,

		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),

		PublicKeyBits: publicKeyBits(cert),

		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		IPAddresses:    ipToStrings(cert.IPAddresses),
		URIs:           urisToStrings(cert.URIs),

		KeyUsage:    keyUsageStrings(cert.KeyUsage),
		ExtKeyUsage: extKeyUsageStrings(cert.ExtKeyUsage),

		OCSPServers:           cert.OCSPServer,
		IssuingCertificateURL: cert.IssuingCertificateURL,
		CRLDistributionPoints: cert.CRLDistributionPoints,

		SHA1Fingerprint:   hashSHA1(cert.Raw),
		SHA256Fingerprint: hashSHA256(cert.Raw),
		SHA512Fingerprint: hashSHA512(cert.Raw),

		PEM: pemEncode(cert),
		Raw: cert,
	}
}

// ---------------- helpers ----------------

func hashSHA1(b []byte) string {
	h := sha1.Sum(b)
	return hex.EncodeToString(h[:])
}

func hashSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hashSHA512(b []byte) string {
	h := sha512.Sum512(b)
	return hex.EncodeToString(h[:])
}

func ipToStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func urisToStrings(uris []*url.URL) []string {
	out := make([]string, len(uris))
	for i, u := range uris {
		out[i] = u.String()
	}
	return out
}

func keyUsageStrings(ku x509.KeyUsage) []string {
	var res []string

	if ku&x509.KeyUsageDigitalSignature != 0 {
		res = append(res, "DigitalSignature")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		res = append(res, "KeyEncipherment")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		res = append(res, "CertSign")
	}

	return res
}

func extKeyUsageStrings(eku []x509.ExtKeyUsage) []string {
	var res []string

	for _, k := range eku {
		res = append(res, fmt.Sprintf("%d", k))
	}

	return res
}

func pemEncode(cert *x509.Certificate) string {

	var buf bytes.Buffer

	err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err != nil {
		return ""
	}

	return buf.String()
}

func publicKeyBits(cert *x509.Certificate) int {

	switch pub := cert.PublicKey.(type) {

	case *rsa.PublicKey:
		return pub.Size() * 8

	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			return pub.Curve.Params().BitSize
		}
		return 0

	default:
		return 0
	}
}
