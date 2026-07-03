package collect

import (
	"net"

	"github.com/cyd01/tlsclient/pkg/client"
)

// CollectTCP enrichit le report avec des informations DNS supplémentaires.
func CollectTCP(c *client.Connection) error {

	host, _, err := net.SplitHostPort(c.Report.TCP.RemoteAddr)
	if err != nil {
		return err
	}

	// Résolution DNS complète (toutes les IPs possibles)
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			c.Report.TCP.RemoteIPs = append(c.Report.TCP.RemoteIPs, ip)
		}
	}

	return nil
}
