package collect

import (
	"github.com/cyd01/tlsclient/pkg/cert"
	"github.com/cyd01/tlsclient/pkg/client"
)

// Verify applique la validation TLS.
func Verify(c *client.Connection) error {
	return cert.Verify(c)
}
