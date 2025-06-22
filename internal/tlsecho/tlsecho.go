package tlsecho

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/template"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ajcross/tlsecho/internal/certaux"
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

type Config struct {
	KeyFile       string
	CertFile      string
	EnvRE         string
	Addr          string
	Verbose       bool
	UseTLS        bool
	TLSMaxVersion uint16
	CN            string
	SetCookie     bool
	UseHttp3      bool
	WriteCertKey  bool
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

func Start(config Config) {

	th := makeTLSHelloMap()
	helloTemplate := getTLSHelloTemplate()
	httpTemplate := getTemplate()

	envvarsTemplate := getEnvVarTemplate()
	envvars := getEnvVars(config.EnvRE)
	if len(envvars) > 0 {
		templateExecute(envvarsTemplate, envvars, nil, config.Verbose)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if config.SetCookie {
			cookie := &http.Cookie{
				Name:  "cookie",
				Value: "Cookies are delicious delicacies",
			}
			http.SetCookie(w, cookie)
		}
		if config.UseHttp3 {
			// Set the age to just 60s, since this server is for testing
			w.Header().Set("alt-svc", "h3=\""+config.Addr+"\"; ma=60, h3-29=\""+config.Addr+"\"; ma=60")
		}
		if config.UseTLS {
			// we set console output to false as hello messages are logged as soon as they arrive
			var cli = th.getByAddrNet(r.RemoteAddr, r.Context().Value(http.LocalAddrContextKey).(net.Addr).Network())
			if cli != nil {
				templateExecute(helloTemplate, cli, w, false)
			}
		}
		if len(envvars) > 0 {
			templateExecute(envvarsTemplate, envvars, w, config.Verbose)
		}
		templateExecute(httpTemplate, r, w, config.Verbose)
	})

	if config.UseTLS {
		startHttps(config, th, helloTemplate)
	} else {
		startHttp(config)
	}
}
func startHttps(config Config, th *tlsHelloMap, helloTemplate *template.Template) {
	var certificate tls.Certificate
	var err error
	if config.WriteCertKey || config.KeyFile == "" {
		certificate, err = certaux.GenX509KeyPair(config.CN)
		if err == nil && config.WriteCertKey {
			err = certaux.SaveX509KeyPair(certificate, config.CertFile, config.KeyFile)
		}
	} else {
		certificate, err = tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
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
			templateExecute(helloTemplate, chi, nil, config.Verbose)
			return &certificate, nil
		},
		MaxVersion: config.TLSMaxVersion,
	}

	if config.UseHttp3 {
		quicConf := &quic.Config{}
		http3Server := &http3.Server{
			Addr:       config.Addr,
			TLSConfig:  tlsconfig,
			QUICConfig: quicConf,
		}
		go func() {
			log.Printf("HTTP3 server listening on %s", config.Addr)
			log.Fatal(http3Server.ListenAndServe())
		}()
	}
	var ml myListener
	var l net.Listener
	l, err = net.Listen("tcp", config.Addr)

	if err != nil {
		log.Fatal(err)
	}

	ml = myListener{
		l,
		th,
	}

	httpServer := &http.Server{
		Addr:      config.Addr,
		TLSConfig: tlsconfig,
	}
	log.Printf("HTTP server listening on %s", config.Addr)
	log.Fatal(httpServer.ServeTLS(ml, "", ""))
}
func startHttp(config Config) {
	httpServer := &http.Server{
		Addr: config.Addr,
	}
	log.Printf("HTTP server listening on %s", config.Addr)
	log.Fatal(httpServer.ListenAndServe())
}
