package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cyd01/tlsclient/pkg/client"
	"github.com/cyd01/tlsclient/pkg/collect"
	"github.com/cyd01/tlsclient/pkg/output"
	"github.com/cyd01/tlsclient/pkg/probe"
)

func main() {

	var (
		timeout   = flag.Duration("timeout", 10*time.Second, "timeout")
		jsonOut   = flag.Bool("json", false, "output JSON")
		insecure  = flag.Bool("insecure", false, "skip verification")
		alpn      = flag.String("alpn", "", "ALPN protocols comma separated")
		sni       = flag.String("sni", "", "override SNI")
		showCerts = flag.Bool("showcerts", false, "show full certificate chain (PEM)")
		probeALPN = flag.String("force-alpn", "h2,http/1.1", "coma separated list of protocols")
		probeFlag = flag.Bool("probe-alpn", false, "probe ALPN and HTTP/3 support")
		probeTLS  = flag.Bool("probe-tls", false, "probe TLS versions and cipher suites")
	)

	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("usage: tlsclient [options] host:port")
		os.Exit(1)
	}

	addr := flag.Arg(0)
	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}

	if *probeTLS {

		fmt.Println("TLS Versions")
		fmt.Println("------------")

		versions := probe.ProbeTLSVersions(addr, *sni)

		for _, v := range versions {
			status := "NO"
			if v.OK {
				status = "YES"
			}
			fmt.Printf("%-7s %s\n", v.Version, status)
		}

		var ciphers []probe.CipherResult
		for _, v := range versions {
			if (v.Version == "TLS1.0") && (v.OK) {
				fmt.Println("\nCipher Suites (TLS 1.0)")
				fmt.Println("-----------------------")
				ciphers = probe.ProbeCiphersTLS10(addr, *sni)
				for _, c := range ciphers {
					status := "NO"
					if c.OK {
						status = "YES"
					}
					fmt.Printf("%-45s %s\n", c.Cipher, status)
				}
			} else if (v.Version == "TLS1.1") && (v.OK) {
				fmt.Println("\nCipher Suites (TLS 1.1)")
				fmt.Println("-----------------------")
				ciphers = probe.ProbeCiphersTLS11(addr, *sni)
				for _, c := range ciphers {
					status := "NO"
					if c.OK {
						status = "YES"
					}
					fmt.Printf("%-45s %s\n", c.Cipher, status)
				}
			} else if (v.Version == "TLS1.2") && (v.OK) {
				fmt.Println("\nCipher Suites (TLS 1.2)")
				fmt.Println("-----------------------")
				ciphers = probe.ProbeCiphersTLS12(addr, *sni)
				for _, c := range ciphers {
					status := "NO"
					if c.OK {
						status = "YES"
					}
					fmt.Printf("%-45s %s\n", c.Cipher, status)
				}
			} else if (v.Version == "TLS1.3") && (v.OK) {
				fmt.Println("\nCipher Suites (TLS 1.3)")
				fmt.Println("-----------------------")
				ciphers = probe.ProbeCiphersTLS13(addr, *sni)
				for _, c := range ciphers {
					status := "NO"
					if c.OK {
						status = "YES"
					}
					fmt.Printf("%-45s %s\n", c.Cipher, status)
				}
			}
		}
		return
	}

	/*protocols := [][]string{
		{"h2"},
		{"http/1.1"},
		{"acme-tls/1"},
		{"mqtt"},
		{"imap"},
	}*/
	protocols := []string{"h2", "http/1.1"}
	if len(*probeALPN) > 0 {
		protocols = strings.Split(*probeALPN, ",")
	}

	if *probeFlag {
		fmt.Println("ALPN (TCP/TLS)")
		fmt.Println("----------------------")

		results := probe.ProbeALPN(addr, *sni, protocols)

		for _, r := range results {
			status := "NO"
			if r.OK {
				status = "OK"
			}
			fmt.Printf("  %-12s %s\n", r.Protocol, status)
		}

		fmt.Println("\nHTTP/3 (QUIC)")
		fmt.Println("----------------------")

		if probe.ProbeH3(addr, *sni) {
			fmt.Println("  h3          YES")
		} else {
			fmt.Println("  h3          NO")
		}
		return
	}

	opts := client.Options{
		Address:            addr,
		Timeout:            *timeout,
		InsecureSkipVerify: *insecure,
		NextProtos:         protocols,
	}

	if *sni != "" {
		opts.ServerName = *sni
	}

	if *alpn != "" {
		opts.NextProtos = splitCSV(*alpn)
	}

	conn, err := client.Connect(opts)
	if err != nil {
		fmt.Println("connect error:", err)
		os.Exit(1)
	}
	defer conn.Close()
	conn.ShowCerts = *showCerts

	// ---------------- Collectors ----------------

	collect.CollectTCP(conn)
	collect.CollectTLS(conn)
	collect.CollectCertificates(conn)

	// ---------------- Verification ----------------

	_ = collect.Verify(conn) // on l’ajoute juste après

	// ---------------- Output ----------------

	if *jsonOut {
		_ = output.PrintJSON(conn)
	} else {
		output.PrintText(conn)
	}
}

func splitCSV(s string) []string {
	var res []string
	for _, p := range splitAndTrim(s, ",") {
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func splitAndTrim(s, sep string) []string {
	var out []string
	for _, p := range split(s, sep) {
		p = trim(p)
		out = append(out, p)
	}
	return out
}

func split(s, sep string) []string {
	return []string{} // simplifié volontairement
}

func trim(s string) string {
	return s
}
