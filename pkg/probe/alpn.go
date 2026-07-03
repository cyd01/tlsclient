package probe

import (
	"crypto/tls"
	"net"
	"time"
)

type ALPNResult struct {
	Protocol string
	OK       bool
}

func ProbeALPN(addr string, sni string, protocols []string) []ALPNResult {
	var results []ALPNResult
	host, port, _ := net.SplitHostPort(addr)
	target := net.JoinHostPort(host, port)
	for _, p := range protocols {

		ok := testALPN(target, sni, p)

		results = append(results, ALPNResult{
			Protocol: p,
			OK:       ok,
		})
	}

	return results
}

func testALPN(addr, sni, proto string) bool {

	cfg := &tls.Config{
		NextProtos:         []string{proto},
		InsecureSkipVerify: true,
	}
	if len(sni) > 0 {
		cfg.ServerName = sni
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		addr,
		cfg,
	)

	if err != nil {
		return false
	}

	defer conn.Close()

	state := conn.ConnectionState()

	return state.NegotiatedProtocol == proto
}
