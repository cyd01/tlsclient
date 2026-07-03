package probe

import (
	"crypto/tls"
	"net"
	"time"
)

type TLSVersionResult struct {
	Version string
	OK      bool
}

func ProbeTLSVersions(addr, sni string) []TLSVersionResult {

	versions := []struct {
		name    string
		version uint16
	}{
		{"TLS1.0", tls.VersionTLS10},
		{"TLS1.1", tls.VersionTLS11},
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
	}

	var results []TLSVersionResult

	for _, v := range versions {
		cfg := &tls.Config{
			ServerName:         sni,
			MinVersion:         v.version,
			MaxVersion:         v.version,
			InsecureSkipVerify: true,
		}
		ok := testTLSVersion(addr, cfg)
		results = append(results, TLSVersionResult{
			Version: v.name,
			OK:      ok,
		})
	}

	return results
}

func testTLSVersion(addr string, cfg *tls.Config) bool {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		addr,
		cfg,
	)

	if err != nil {
		//		fmt.Printf("%s: %v\n", tlsinfo.VersionName(cfg.MaxVersion), err)
		return false
	}

	conn.Close()
	return true
}
