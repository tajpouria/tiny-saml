package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/tajpouria/tiny-saml/routes"
)

const (
	idpCertPath = "samples/certificate.pem"
	idpPkPath   = "samples/private_key.pem"
)

func main() {
	// Read private key
	idpPkFile, err := os.Open(idpPkPath)
	if err != nil {
		log.Fatalf("Failed to open idP pk file: %v", err)
	}
	idpPkB, err := io.ReadAll(idpPkFile)
	if err != nil {
		log.Fatalf("Failed to read idP PK file: %v", err)
	}
	idpPkBlock, _ := pem.Decode(idpPkB)
	if idpPkBlock == nil {
		log.Fatalf("Failed to PEM parse idP PK block")
	}
	idpPrivateKey, err := x509.ParsePKCS1PrivateKey(idpPkBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to X.509 parse idP PK block: %v", err)
	}

	// Read certificate
	idpCertFile, err := os.Open(idpCertPath)
	if err != nil {
		log.Fatalf("Failed to open idP cert file: %v", err)
	}
	idpCertB, err := io.ReadAll(idpCertFile)
	if err != nil {
		log.Fatalf("Failed to read idP cert file: %v", err)
	}
	idpCertBlock, _ := pem.Decode(idpCertB)
	if idpCertBlock == nil {
		log.Fatalf("Failed to PEM parse idP certificate: %s", idpCertPath)
	}
	idpCert, err := x509.ParseCertificate(idpCertBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to X.509 parse idP certificate block %v", err)
	}
	idpPublicKey, ok := idpCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Public key must be *rsa.PublicKey")
	}

	mux := http.NewServeMux()
	routes.InitSP(mux, idpPublicKey)
	routes.InitIDP(mux, idpPrivateKey)
	fmt.Println("Server running at http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", mux))
}
