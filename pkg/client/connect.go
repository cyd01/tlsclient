package client

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/cyd01/tlsclient/pkg/types"
)

// Options décrit tous les paramètres d'une connexion.
// De nouveaux champs pourront être ajoutés facilement par la suite.
type Options struct {
	Address string

	// Timeout global de connexion.
	Timeout time.Duration

	// Nom SNI.
	// Si vide, il est déduit automatiquement de Address.
	ServerName string

	// Versions TLS.
	MinVersion uint16
	MaxVersion uint16

	// Suites cryptographiques (TLS ≤1.2).
	CipherSuites []uint16

	// ALPN proposés.
	NextProtos []string

	// Vérification du certificat.
	InsecureSkipVerify bool

	// Authentification client (mTLS).
	Certificates []tls.Certificate
	RootCAs      *x509.CertPool
}

// Connection regroupe tous les objets utiles pendant
// la collecte d'informations.
type Connection struct {
	Conn      *tls.Conn
	TCPConn   net.Conn
	TLSState  tls.ConnectionState
	Report    *types.Report
	TLSConfig *tls.Config

	ShowCerts bool
}

// Connect établit une connexion TCP puis TLS.
func Connect(opts Options) (*Connection, error) {

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	host, _, err := net.SplitHostPort(opts.Address)
	if err != nil {
		return nil, err
	}

	if opts.ServerName == "" {
		opts.ServerName = host
	}

	host, port, err := net.SplitHostPort(opts.Address)
	if err != nil {
		return nil, err
	}

	ips, _ := net.LookupIP(host)

	report := &types.Report{
		Target: types.TargetInfo{
			Address: opts.Address,
			Host:    host,
			Port:    port,
		},
		Timestamp: time.Now(),
	}

	for _, ip := range ips {
		report.TCP.RemoteIPs = append(report.TCP.RemoteIPs, ip)
	}

	//-------------------------------------------------------
	// TCP
	//-------------------------------------------------------

	start := time.Now()

	dialer := net.Dialer{
		Timeout: opts.Timeout,
	}

	tcpConn, err := dialer.Dial("tcp", opts.Address)
	if err != nil {
		return nil, err
	}

	report.Timing.TCPConnect = time.Since(start)

	//-------------------------------------------------------
	// Informations TCP
	//-------------------------------------------------------

	local := tcpConn.LocalAddr().(*net.TCPAddr)
	remote := tcpConn.RemoteAddr().(*net.TCPAddr)

	report.TCP.Network = "tcp"

	report.TCP.LocalAddr = local.String()
	report.TCP.RemoteAddr = remote.String()

	report.TCP.LocalIP = local.IP
	report.TCP.RemoteIP = remote.IP

	report.TCP.LocalPort = local.Port
	report.TCP.RemotePort = remote.Port

	//-------------------------------------------------------
	// TLS
	//-------------------------------------------------------

	cfg := &tls.Config{
		ServerName:         opts.ServerName,
		MinVersion:         opts.MinVersion,
		MaxVersion:         opts.MaxVersion,
		NextProtos:         opts.NextProtos,
		CipherSuites:       opts.CipherSuites,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		Certificates:       opts.Certificates,
		RootCAs:            opts.RootCAs,
	}

	tlsConn := tls.Client(tcpConn, cfg)

	start = time.Now()

	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}

	report.Timing.TLSHandshake = time.Since(start)
	report.Timing.Total =
		report.Timing.TCPConnect +
			report.Timing.TLSHandshake

	state := tlsConn.ConnectionState()

	return &Connection{
		Conn:      tlsConn,
		TCPConn:   tcpConn,
		TLSState:  state,
		Report:    report,
		TLSConfig: cfg,
	}, nil
}

// Close ferme proprement la connexion.
func (c *Connection) Close() {

	if c == nil {
		return
	}

	if c.Conn != nil {
		c.Conn.Close()
	}
}
