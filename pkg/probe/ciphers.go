package probe

import (
	"crypto/tls"
	"net"
	"slices"
	"time"
)

type CipherResult struct {
	Cipher string
	OK     bool
}

/* generic for TLS 1.0, 1.1, 1.2 */
func ProbeCiphers(addr, sni string, version uint16, ciphers []*tls.CipherSuite) []CipherResult {
	var results []CipherResult
	for _, cipher := range ciphers {
		if slices.Contains(cipher.SupportedVersions, version) {
			cfg := &tls.Config{
				ServerName:         sni,
				MinVersion:         version,
				MaxVersion:         version,
				CipherSuites:       []uint16{cipher.ID},
				InsecureSkipVerify: true,
			}
			results = append(results, CipherResult{
				Cipher: tls.CipherSuiteName(cipher.ID),
				OK:     testTLSCipher(addr, cfg),
			})
		}
	}
	return results
}

func ProbeCiphersTLS10(addr, sni string) []CipherResult {
	return ProbeCiphers(addr, sni, tls.VersionTLS10, tls.CipherSuites())
}

func ProbeCiphersTLS11(addr, sni string) []CipherResult {
	return ProbeCiphers(addr, sni, tls.VersionTLS11, tls.CipherSuites())
}

func ProbeCiphersTLS12(addr, sni string) []CipherResult {
	return ProbeCiphers(addr, sni, tls.VersionTLS12, tls.CipherSuites())
}

func ProbeCiphersTLS13(addr, sni string) []CipherResult {
	return ProbeCiphers(addr, sni, tls.VersionTLS13, tls.CipherSuites())
}

func testTLSCipher(addr string, cfg *tls.Config) bool {
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
	return true
}
