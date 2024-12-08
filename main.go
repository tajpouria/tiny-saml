package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/tajpouria/tiny-saml/internal/dsig"
)

const (
	assertResPath = "samples/sample.xml"
	idpCertPath   = "samples/certificate.pem"
	idpPkPath     = "samples/private_key.pem"
)

type AssertionRes struct {
	FavoriteNumber int    `xml:"favoriteNumber,attr"`
	FavoriteQuote  string `xml:"favoriteQuote"`
	Signature      dsig.Signature
}

func main() {
	// Read assertion response

	assertResFile, err := os.Open(assertResPath)
	if err != nil {
		log.Fatalf("Failed to open assertion response file: %v", err)
	}

	assertResB, err := io.ReadAll(assertResFile)
	if err != nil {
		log.Fatalf("Failed to read assertion response file: %v", err)
	}

	var assertRes AssertionRes
	err = xml.Unmarshal(assertResB, &assertRes)
	if err != nil {
		log.Fatalf("Failed to unmarshal assertion response: %v", err)
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

	err = assertRes.Signature.Sign(assertResB, idpPrivateKey)
	if err != nil {
	}

	err = assertRes.Signature.Verify(assertResB, idpPublicKey)
	if err != nil {
		log.Fatalf("Failed to verify assertion response %v", err)
	}

	fmt.Println("Assertion response signature is valid!")
}
