package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type EnvVar struct {
	Name, Value string
}

func getEnvVars(res string) []EnvVar {
	// loads all the env variables that match a regexp
	envvars := []EnvVar{}

	re, err := regexp.Compile(res)
	if err != nil {
		log.Println(err)
		return envvars
	}

	for _, env := range os.Environ() {
		envvar := strings.SplitN(env, "=", 2)
		if re.MatchString(envvar[0]) {
			e := EnvVar{envvar[0], envvar[1]}
			envvars = append(envvars, e)
		}
	}
	return envvars
}

func genCertificate(cn string, certPrivKey *rsa.PrivateKey) []byte {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Nanosecond())),
		Subject: pkix.Name{
			Organization:  []string{"San Tome Silver Mine"},
			Country:       []string{"CT"},
			Province:      []string{"Sulaco"},
			Locality:      []string{"Sulaco"},
			StreetAddress: []string{"Street of the Constitution"},
			PostalCode:    []string{"1904"},
			CommonName:    cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		log.Println(err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return certPEM.Bytes()
}

func genX509KeyPair(cn string) (tls.Certificate, error) {
	var certPEM, keyPEM []byte
	var err error
	var certificate tls.Certificate

	log.Printf("No certificate specified, generating a certificate for cn=%s", cn)
	var key *rsa.PrivateKey
	key, err = rsa.GenerateKey(rand.Reader, 4096)
	certPEM = genCertificate(cn, key)
	keyPEMBuffer := new(bytes.Buffer)
	pem.Encode(keyPEMBuffer, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	keyPEM = keyPEMBuffer.Bytes()
	certificate, err = tls.X509KeyPair(certPEM, keyPEM)
	log.Printf("Certificate generated")
	return certificate, err
}

// support functions for templates
var fmap template.FuncMap = template.FuncMap{
	"CipherSuiteName": tls.CipherSuiteName,
	"TLSVersion": func(version uint16) string {
		switch version {
		case tls.VersionTLS10:
			return "TLS1.0"
		case tls.VersionTLS11:
			return "TLS1.1"
		case tls.VersionTLS12:
			return "TLS1.2"
		case tls.VersionTLS13:
			return "TLS1.3"
		case tls.VersionSSL30:
			return "SSL30 Deprecated!!"
		default:
			return fmt.Sprintf("Unknown TLS Version (0x%x)", version)
		}
	},
	"PEM": func(cert x509.Certificate) *bytes.Buffer {
		certPEM := new(bytes.Buffer)
		pem.Encode(certPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		return certPEM
	},
	"DidResume": func(conn *tls.Conn) string {
		if conn.ConnectionState().DidResume {
			return "true"
		} else {
			return "false"
		}
	},
	"KeyUsage": func(keyusage x509.KeyUsage) string {
		var kusage string
		if keyusage&x509.KeyUsageDigitalSignature != 0 {
			kusage += "KeyUsageDigitalSignature "
		}
		if keyusage&x509.KeyUsageContentCommitment != 0 {
			kusage += "KeyUsageContentCommitment "
		}
		if keyusage&x509.KeyUsageKeyEncipherment != 0 {
			kusage += "KeyUsageKeyEncipherment "
		}
		if keyusage&x509.KeyUsageDataEncipherment != 0 {
			kusage += "KeyUsageDataEncipherment "
		}
		if keyusage&x509.KeyUsageKeyAgreement != 0 {
			kusage += "KeyUsageKeyAgreement "
		}
		if keyusage&x509.KeyUsageCertSign != 0 {
			kusage += "KeyUsageCertSign "
		}
		if keyusage&x509.KeyUsageCRLSign != 0 {
			kusage += "KeyUsageCRLSign "
		}
		if keyusage&x509.KeyUsageEncipherOnly != 0 {
			kusage += "KeyUsageEncipherOnly "
		}
		if keyusage&x509.KeyUsageDecipherOnly != 0 {
			kusage += "KeyUsageDecipherOnly "
		}
		return kusage
	},
	"LocalAddr": func(req *http.Request) string {
		return req.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
	},
}

func getTLSHelloTemplate() *template.Template {
	const temp = `
-- TLS hello --
ServerName:        {{ .ServerName }}
SupportedVersions: {{ range .SupportedVersions }} {{ . | TLSVersion }}{{ end }} 
SupportedProtos:   {{ range .SupportedProtos }} {{ . }}{{ end }}
CipherSuites:      {{ range .CipherSuites }} {{ . | CipherSuiteName }}{{ end }}
RemoteAddr:        {{ .Conn.RemoteAddr }}/{{ .Conn.RemoteAddr.Network }}
LocalAddr:         {{ .Conn.LocalAddr }}/{{ .Conn.LocalAddr.Network }}

`
	t := template.Must(template.New("temp").Funcs(fmap).Parse(temp))
	return t
}

func templateExecute(t *template.Template, data any, wr io.Writer, tolog bool) {
	var err error
	err = nil
	if wr != nil {
		err = t.Execute(wr, data)
	}
	if err == nil && tolog {
		err = t.Execute(log.Writer(), data)
	}
	if err != nil {
		fmt.Fprintf(wr, err.Error(), http.StatusInternalServerError)
		log.Printf(err.Error(), http.StatusInternalServerError)
	}
}
func getEnvVarTemplate() *template.Template {
	const temp = `
-- Environment --
{{ range $envvar := . }}{{ $envvar.Name }}: {{ $envvar.Value }}
{{end}}`

	t := template.Must(template.New("temp").Funcs(fmap).Parse(temp))
	return t
}

func getTemplate() *template.Template {
	const temp = `
-- Connection --
RemoteAddr: {{.RemoteAddr}}
LocalAddr: {{ . | LocalAddr }}
{{ if .TLS }}
--  TLS  --
ServerName:         {{ .TLS.ServerName }}
Version:            {{ .TLS.Version | TLSVersion }}
NegociatedProtocol: {{ .TLS.NegotiatedProtocol }}
CipherSuite:        {{ .TLS.CipherSuite | CipherSuiteName }} 
DidResume:          {{ .TLS.DidResume }}
{{ range .TLS.PeerCertificates }}
 Subject:      {{ .Subject }}
 Issuer:       {{ .Issuer }}
 SerialNumber: {{ .SerialNumber }}
 NotBefore:    {{ .NotBefore }}
 NotAfter:     {{ .NotAfter }}
 KeyUsage:     {{ .KeyUsage | KeyUsage }}
 PEM:          
{{ . | PEM }}{{ end }}{{ end }}
--  HTTP  --
Proto: {{ .Proto }}
Host: {{ .Host }}
Method: {{ .Method }}
URI: {{ .RequestURI }}
Headers:
{{ range $key, $values := .Header }}{{ range $value := $values }}  {{ $key }}: {{ $value }} 
{{end}}{{end}}`

	t := template.Must(template.New("temp").Funcs(fmap).Parse(temp))
	return t
}
func usageAndExit(error string) {
	fmt.Fprintln(os.Stderr, error)
	flag.Usage()
	os.Exit(-2)
}

type tlsHelloMap struct {
	addressHelloMap map[string]*tls.ClientHelloInfo
	mutex           *sync.RWMutex
}

func makeTLSHelloMap() *tlsHelloMap {
	var mutex sync.RWMutex
	return &tlsHelloMap{
		make(map[string]*tls.ClientHelloInfo),
		&mutex,
	}
}
func (c *tlsHelloMap) get(addr net.Addr) *tls.ClientHelloInfo {
	return c.getByAddrNet(addr.String(), addr.Network())
}
func (c *tlsHelloMap) getByAddrNet(addr string, network string) *tls.ClientHelloInfo {
	c.mutex.RLock()
	cli := c.addressHelloMap[addr+"/"+network]
	c.mutex.RUnlock()
	return cli
}

func (c *tlsHelloMap) set(addr net.Addr, cli *tls.ClientHelloInfo) {
	c.mutex.Lock()
	c.addressHelloMap[addr.String()+"/"+addr.Network()] = cli
	c.mutex.Unlock()
}

func (c *tlsHelloMap) Delete(nc net.Conn) {
	c.mutex.Lock()
	delete(c.addressHelloMap, nc.RemoteAddr().String()+"/"+nc.RemoteAddr().Network())
	c.mutex.Unlock()
}

type myListener struct {
	net.Listener
	tlsHelloMap *tlsHelloMap
}

type myConn struct {
	net.Conn
	tlsHelloMap *tlsHelloMap
}

func (mc myConn) Close() (e error) {
	mc.tlsHelloMap.Delete(mc)
	return net.Conn.Close(mc.Conn)
}

func (ml myListener) Accept() (net.Conn, error) {
	c, e := net.Listener.Accept(ml.Listener)
	mc := myConn{
		c,
		ml.tlsHelloMap,
	}
	return mc, e
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var keyFile, certFile string
	var envre string
	var addr string
	var verbose bool
	var useTLS bool
	var cn string
	var setCookie bool
	var useHttp3 bool

	flag.StringVar(&keyFile, "key", "", "Certificate key file")
	flag.StringVar(&certFile, "cert", "", "Certificate file")
	flag.StringVar(&addr, "addr", ":8443", "service address")
	flag.BoolVar(&verbose, "verbose", true, "verbose")
	flag.BoolVar(&verbose, "v", true, "verbose")
	flag.BoolVar(&useTLS, "tls", true, "tls")
	flag.StringVar(&cn, "cn", "localhost", "cn for the automatically generated certificate")
	flag.BoolVar(&setCookie, "set-cookie", true, "set cookie")
	flag.StringVar(&envre, "env-re", "^TLSECHO", "regexp to filter environment variables to output")
	flag.BoolVar(&useHttp3, "http3", false, "enable http3")

	flag.Parse()
	if flag.NArg() != 0 {
		usageAndExit("Extra arguments not supported")
	}
	if (keyFile == "") != (certFile == "") {
		usageAndExit("keyfile and certfile, set both or none")
	}
	if keyFile != "" && !useTLS {
		usageAndExit("tls disabled and tls credentials set is not supported")
	}
	if keyFile != "" && cn != "localhost" {
		usageAndExit("you can't set both cn and certificate files")
	}
	if useHttp3 && !useTLS {
		usageAndExit("http3 requires tls")
	}

	th := makeTLSHelloMap()

	helloTemplate := getTLSHelloTemplate()
	httpTemplate := getTemplate()

	envvarsTemplate := getEnvVarTemplate()
	envvars := getEnvVars(envre)
	if len(envvars) > 0 {
		templateExecute(envvarsTemplate, envvars, nil, verbose)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if setCookie {
			cookie := &http.Cookie{
				Name:  "cookie",
				Value: "Cookies are delicious delicacies",
			}
			http.SetCookie(w, cookie)
		}
		if useHttp3 {
			// Set the age to just 60s, since this server is for testing
			w.Header().Set("alt-svc", "h3=\""+addr+"\"; ma=60, h3-29=\""+addr+"\"; ma=60")
		}
		if useTLS {
			// we set console output to false as hello messages are logged as soon as they arrive
			var cli = th.getByAddrNet(r.RemoteAddr, r.Context().Value(http.LocalAddrContextKey).(net.Addr).Network())
			if cli != nil {
				templateExecute(helloTemplate, cli, w, false)
			}
		}
		if len(envvars) > 0 {
			templateExecute(envvarsTemplate, envvars, w, verbose)
		}
		templateExecute(httpTemplate, r, w, verbose)
	})

	if useTLS {
		var certificate tls.Certificate
		var err error
		if keyFile == "" {
			certificate, err = genX509KeyPair(cn)
		} else {
			certificate, err = tls.LoadX509KeyPair(certFile, keyFile)
		}
		if err != nil {
			log.Fatal(err.Error())
		}
		var tlsconfig *tls.Config

		tlsconfig = &tls.Config{
			ClientAuth: tls.RequestClientCert,
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			        th.set(chi.Conn.RemoteAddr(), chi)
				// with TLS, log the hello info as soon as it arrives, just in case the connection is aborted
				templateExecute(helloTemplate, chi, nil, verbose)
				return &certificate, nil
			},
		}

		if useHttp3 {
			quicConf := &quic.Config{}
			http3Server := &http3.Server{
				Addr:       addr,
				TLSConfig:  tlsconfig,
				QUICConfig: quicConf,
			}
			go func() {
				log.Printf("HTTP3 server listening on %s", addr)
				log.Fatal(http3Server.ListenAndServe())
			}()
		}
		var ml myListener
		var l net.Listener
		l, err = net.Listen("tcp", addr)

		if err != nil {
			log.Fatal(err)
		}

		ml = myListener{
			l,
			th,
		}

		httpServer := &http.Server{
			Addr:      addr,
			TLSConfig: tlsconfig,
		}
		log.Printf("HTTP server listening on %s", addr)
		log.Fatal(httpServer.ServeTLS(ml, "", ""))

	} else {
		httpServer := &http.Server{
			Addr: addr,
		}
		log.Printf("HTTP server listening on %s", addr)
		log.Fatal(httpServer.ListenAndServe())
	}
}
