package main

import (
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
	idpCertPath   = "samples/sample.pem"
)

type AssertionRes struct {
	FavoriteNumber int    `xml:"favoriteNumber,attr"`
	FavoriteQuote  string `xml:"favoriteQuote"`
	Signature      dsig.Signature
}

func main() {
	assertResFile, err := os.Open(assertResPath)
	if err != nil {
		log.Fatalf("Failed to open assertion response file: %v", err)
	}

	assertResContent, err := io.ReadAll(assertResFile)
	if err != nil {
		log.Fatalf("Failed to read assertion response file: %v", err)
	}

	var assertRes AssertionRes
	err = xml.Unmarshal(assertResContent, &assertRes)
	if err != nil {
		log.Fatalf("Failed to unmarshal assertion response: %v", err)
	}

	fmt.Printf("assertRes: %+v\n", assertRes)

	idpCertFile, err := os.Open(idpCertPath)
	if err != nil {
		log.Fatalf("Failed to open idP cert file: %v", err)
	}

	idpCertContent, err := io.ReadAll(idpCertFile)
	if err != nil {
		log.Fatalf("Failed to read idP cert file: %v", err)
	}

	idpCertBlock, _ := pem.Decode(idpCertContent)
	if idpCertBlock == nil {
		log.Fatalf("Failed to parse idP PEM certificate: %s", idpCertPath)
	}

	idpCert, err := x509.ParseCertificate(idpCertBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse idP certificate block")
	}

	fmt.Printf("idpCertBlock type, headers: %v, %+v\n", idpCertBlock.Type, idpCertBlock.Headers)

	err = assertRes.Signature.Verify(assertResContent, idpCert)
	if err != nil {
		log.Fatalf("Failed to verify assertion response %v", err)
	}
}
