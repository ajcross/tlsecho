package certaux

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func GenX509KeyPair(cn string) (tls.Certificate, error) {
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

// saveCertificatePEM writes an x509.Certificate to a PEM-encoded file.
func saveCertificatePEM(cert *x509.Certificate, filename string) error {
	permissions := os.FileMode(0644)
	certFile, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, permissions)
	if err != nil {
		return fmt.Errorf("failed to create certificate file %s: %w", filename, err)
	}
	defer certFile.Close()

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	if err := pem.Encode(certFile, pemBlock); err != nil {
		return fmt.Errorf("failed to write certificate PEM to %s: %w", filename, err)
	}
	log.Printf("Certificate saved to %s\n", filename)
	return nil
}

// savePrivateKeyPEM writes a private key to a PEM-encoded file.
// It handles both RSA and ECDSA private keys.
func savePrivateKeyPEM(privateKey interface{}, filename string) error {
	permissions := os.FileMode(0644)
	keyFile, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, permissions)
	if err != nil {
		return fmt.Errorf("failed to create key file %s: %w", filename, err)
	}
	defer keyFile.Close()

	var keyBytes []byte
	var keyType string

	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(pk)
		keyType = "PRIVATE KEY" // For PKCS#8
	// case *ecdsa.PrivateKey: // Uncomment if you need ECDSA support
	//      keyBytes, err = x509.MarshalPKCS8PrivateKey(pk)
	//      keyType = "PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported private key type")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		return fmt.Errorf("failed to write private key PEM to %s: %w", filename, err)
	}
	log.Printf("Private key saved to %s\n", filename)
	return nil
}

func SaveX509KeyPair(tlsCert tls.Certificate, certFile, keyFile string) error {
	var err error
	if len(tlsCert.Certificate) > 0 {
		leafCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("Error parsing leaf certificate for saving: %v\n", err)
		}
		err = saveCertificatePEM(leafCert, certFile)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("No certificates found in tls.Certificate to save.")
	}

	// Save the private key
	if tlsCert.PrivateKey != nil {
		err = savePrivateKeyPEM(tlsCert.PrivateKey, keyFile)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("No private key found in tls.Certificate to save.")
	}
	return nil
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
