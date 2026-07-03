package types

import (
	"crypto/x509"
	"net"
	"time"
)

type TargetInfo struct {
	Address string   `json:"address"`
	Host    string   `json:"host"`
	Port    string   `json:"port"`
	IPs     []net.IP `json:"ips,omitempty"`
}

// Report contient toutes les informations récupérées sur une connexion TLS.
type Report struct {
	Target    TargetInfo `json:"target"`
	Timestamp time.Time  `json:"timestamp"`

	TCP          TCPInfo          `json:"tcp"`
	TLS          TLSInfo          `json:"tls"`
	Timing       TimingInfo       `json:"timing"`
	Verification VerificationInfo `json:"verification"`

	Certificates []CertificateInfo `json:"certificates"`
}

// -----------------------------------------------------------------------------
// TCP
// -----------------------------------------------------------------------------

type TCPInfo struct {
	RemoteAddr string `json:"remote_addr"`
	LocalAddr  string `json:"local_addr"`

	RemoteIP   net.IP `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port"`

	LocalIP   net.IP `json:"local_ip,omitempty"`
	LocalPort int    `json:"local_port"`

	Network string `json:"network"`

	// NEW
	RemoteIPs []net.IP `json:"remote_ips,omitempty"`
}

// -----------------------------------------------------------------------------
// Timing
// -----------------------------------------------------------------------------

type TimingInfo struct {
	TCPConnect   time.Duration `json:"tcp_connect"`
	TLSHandshake time.Duration `json:"tls_handshake"`
	Total        time.Duration `json:"total"`
}

// -----------------------------------------------------------------------------
// TLS
// -----------------------------------------------------------------------------

type TLSInfo struct {
	Version            string `json:"version"`
	CipherSuite        string `json:"cipher_suite"`
	ServerName         string `json:"server_name"`
	NegotiatedProtocol string `json:"negotiated_protocol"`
	DidResume          bool   `json:"did_resume"`
	HandshakeComplete  bool   `json:"handshake_complete"`
	MutualTLS          bool   `json:"mutual_tls"`
	ECHAccepted        bool   `json:"ech_accepted"`
}

// -----------------------------------------------------------------------------
// Vérification
// -----------------------------------------------------------------------------

type VerificationInfo struct {
	HostnameValid bool `json:"hostname_valid"`
	ChainValid    bool `json:"chain_valid"`
}

// -----------------------------------------------------------------------------
// Certificats
// -----------------------------------------------------------------------------

type CertificateInfo struct {
	IsLeaf bool `json:"is_leaf"`

	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`

	SerialNumber string `json:"serial_number"`

	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`

	PublicKeyBits int `json:"public_key_bits"`

	DNSNames       []string `json:"dns_names,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`

	KeyUsage    []string `json:"key_usage,omitempty"`
	ExtKeyUsage []string `json:"extended_key_usage,omitempty"`

	OCSPServers           []string `json:"ocsp_servers,omitempty"`
	IssuingCertificateURL []string `json:"issuing_certificate_url,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`

	SHA1Fingerprint   string `json:"sha1_fingerprint"`
	SHA256Fingerprint string `json:"sha256_fingerprint"`
	SHA512Fingerprint string `json:"sha512_fingerprint"`

	PEM string `json:"pem,omitempty"`

	// Certificat original pour les traitements internes.
	Raw *x509.Certificate `json:"-"`
}
