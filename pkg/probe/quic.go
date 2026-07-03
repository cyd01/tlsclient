package probe

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/quic-go/quic-go"
)

func ProbeH3(addr string, sni string) bool {

	tlsConf := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		return false
	}

	_ = conn.CloseWithError(0, "")
	return true
}
