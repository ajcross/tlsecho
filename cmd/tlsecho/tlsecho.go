package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ajcross/tlsecho/internal/tlsecho"
)

func usageAndExit(error string) {
	fmt.Fprintln(os.Stderr, error)
	flag.Usage()
	os.Exit(-2)
}

func parseTLSVersion(version string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "1.0", "tls1.0":
		return tls.VersionTLS10, nil
	case "1.1", "tls1.1":
		return tls.VersionTLS11, nil
	case "1.2", "tls1.2":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s. Supported versions are 1.0, 1.1, 1.2, 1.3", version)
	}
}

func parseArgs() tlsecho.Config {
	var flags tlsecho.Config
	var tlsMaxVersion string
	var err error

	flag.StringVar(&flags.KeyFile, "key", "", "Certificate key file")
	flag.StringVar(&flags.CertFile, "cert", "", "Certificate file")
	flag.StringVar(&flags.Addr, "addr", ":8443", "service address")
	flag.BoolVar(&flags.Verbose, "verbose", true, "verbose")
	flag.BoolVar(&flags.Verbose, "v", true, "verbose")
	flag.BoolVar(&flags.UseTLS, "tls", true, "tls")
	flag.StringVar(&tlsMaxVersion, "tls-max", "1.3", "max tls version [1.1 1.2 1.3]")
	flag.StringVar(&flags.CN, "cn", "localhost", "cn for the automatically generated certificate")
	flag.BoolVar(&flags.SetCookie, "set-cookie", true, "set cookie")
	flag.StringVar(&flags.EnvRE, "env-re", "^TLSECHO", "regexp to filter environment variables to output")
	flag.BoolVar(&flags.UseHttp3, "http3", false, "enable http3")
	flag.BoolVar(&flags.WriteCertKey, "write-files", false, "write generated Certificate and Key files")

	flag.Parse()
	if flag.NArg() != 0 {
		usageAndExit("Extra arguments not supported")
	}

	if (flags.KeyFile == "") != (flags.CertFile == "") {
		usageAndExit("Both --cert and --key must be provided together")
	}
	if flags.KeyFile != "" && !flags.UseTLS {
		usageAndExit("Cannot combine --tls=false with --cert and --key")
	}

	flags.TLSMaxVersion, err = parseTLSVersion(tlsMaxVersion)
	if err != nil {
		usageAndExit(fmt.Sprintf("Error parsing TLS version: %v", err))
	}

	if flags.UseHttp3 && !flags.UseTLS {
		usageAndExit("Cannot combine --tls=false with --http3. HTTP/3 requires tls")
	}
	return flags
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flags := parseArgs()

	tlsecho.Start(flags)
}
