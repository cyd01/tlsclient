package collect

import (
	"crypto/tls"

	"github.com/cyd01/tlsclient/pkg/client"
	"github.com/cyd01/tlsclient/pkg/tlsinfo"
)

// CollectTLS extrait les informations TLS négociées.
func CollectTLS(c *client.Connection) error {

	state := c.TLSState

	c.Report.TLS.Version = tlsinfo.VersionName(state.Version)
	c.Report.TLS.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	c.Report.TLS.ServerName = state.ServerName
	c.Report.TLS.NegotiatedProtocol = state.NegotiatedProtocol
	c.Report.TLS.DidResume = state.DidResume
	c.Report.TLS.HandshakeComplete = state.HandshakeComplete
	c.Report.TLS.ECHAccepted = state.ECHAccepted

	// Mutual TLS détecté si le serveur a demandé un cert client
	c.Report.TLS.MutualTLS = len(state.PeerCertificates) > 0 && len(state.VerifiedChains) > 0

	return nil
}
