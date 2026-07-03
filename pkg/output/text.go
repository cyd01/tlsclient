package output

import (
	"fmt"
	"strings"

	"github.com/cyd01/tlsclient/pkg/client"
)

// PrintText affiche un rendu style openssl s_client.
func PrintText(c *client.Connection) {

	r := c.Report

	fmt.Println("========================================")
	fmt.Println("TLS CLIENT REPORT")
	fmt.Println("========================================")

	// ---------------- TCP ----------------
	fmt.Println("\nTCP")
	fmt.Println("----------------------------------------")
	fmt.Printf("Remote : %s\n", r.TCP.RemoteAddr)
	fmt.Printf("Local  : %s\n", r.TCP.LocalAddr)

	if len(r.TCP.RemoteIPs) > 0 {
		fmt.Println("Resolved IPs:")
		for _, ip := range r.TCP.RemoteIPs {
			fmt.Printf("  - %s\n", ip)
		}
	}

	// ---------------- TLS ----------------
	fmt.Println("\nTLS")
	fmt.Println("----------------------------------------")
	fmt.Printf("Version                : %s\n", r.TLS.Version)
	fmt.Printf("Cipher Suite           : %s\n", r.TLS.CipherSuite)
	fmt.Printf("Server Name            : %s\n", r.TLS.ServerName)
	fmt.Printf("ALPN                   : %s\n", r.TLS.NegotiatedProtocol)
	fmt.Printf("Resumed                : %v\n", r.TLS.DidResume)
	fmt.Printf("Handshake Complete     : %v\n", r.TLS.HandshakeComplete)
	fmt.Printf("Encrypted Client Hello : %v\n", r.TLS.ECHAccepted)

	// ---------------- Verification ----------------
	fmt.Println("\nVerification")
	fmt.Println("----------------------------------------")
	fmt.Printf("Hostname valid : %v\n", r.Verification.HostnameValid)
	fmt.Printf("Chain valid    : %v\n", r.Verification.ChainValid)

	// ---------------- Timing ----------------
	fmt.Println("\nTiming")
	fmt.Println("----------------------------------------")
	fmt.Printf("TCP Connect    : %s\n", r.Timing.TCPConnect)
	fmt.Printf("TLS Handshake  : %s\n", r.Timing.TLSHandshake)
	fmt.Printf("Total          : %s\n", r.Timing.Total)

	// ---------------- Certificates ----------------
	fmt.Println("\nCertificates")
	fmt.Println("----------------------------------------")

	for i, cert := range r.Certificates {
		fmt.Printf("\n[%d] %s\n", i, cert.Subject)
		fmt.Printf("Issuer   : %s\n", cert.Issuer)
		fmt.Printf("Valid    : %s -> %s\n", cert.NotBefore, cert.NotAfter)
		fmt.Printf("SHA256   : %s\n", cert.SHA256Fingerprint)

		if len(cert.DNSNames) > 0 {
			fmt.Println("DNS Names:")
			fmt.Println("  " + strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			fmt.Println("IP Addresses:")
			fmt.Println("  " + strings.Join(cert.IPAddresses, ", "))
		}
		if len(cert.URIs) > 0 {
			fmt.Println("URIs:")
			fmt.Println("  " + strings.Join(cert.URIs, ", "))
		}
		if len(cert.KeyUsage) > 0 {
			fmt.Println("Key Usage:")
			fmt.Println("  " + strings.Join(cert.KeyUsage, ", "))
		}
	}
	if c.ShowCerts {
		fmt.Println("\n===== FULL CERT CHAIN (PEM) =====\n")
		for _, cert := range r.Certificates {
			fmt.Print(cert.PEM)
		}
	}

	fmt.Println("\n========================================")
}
