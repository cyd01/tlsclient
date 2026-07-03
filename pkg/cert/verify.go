package cert

import (
	"crypto/x509"

	"github.com/cyd01/tlsclient/pkg/client"
)

// Verify remplit les infos de validation TLS.
func Verify(c *client.Connection) error {

	state := c.TLSState

	report := &c.Report.Verification

	if len(state.PeerCertificates) == 0 {
		report.ChainValid = false
		return nil
	}

	leaf := state.PeerCertificates[0]

	// ----------------------------
	// Hostname verification
	// ----------------------------
	err := leaf.VerifyHostname(c.TLSConfig.ServerName)
	report.HostnameValid = err == nil

	// ----------------------------
	// Chain verification
	// ----------------------------
	opts := x509.VerifyOptions{
		DNSName:       c.TLSConfig.ServerName,
		Intermediates: x509.NewCertPool(),
		Roots:         c.TLSConfig.RootCAs,
	}

	for _, cert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if opts.Roots == nil {
		var err error
		opts.Roots, err = x509.SystemCertPool()
		if err != nil {
			report.ChainValid = false
			return nil
		}
	}

	_, err = leaf.Verify(opts)
	report.ChainValid = err == nil

	return nil
}
