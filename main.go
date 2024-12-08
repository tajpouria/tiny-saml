package main

import (
	"encoding/pem"
	"io"
	"log"
	"os"

	"github.com/tajpouria/tiny-saml/internal/dsig"
)

type AssertionRes struct {
	FavoriteNumber int    `xml:"favoriteNumber,attr"`
	FavoriteQuote  string `xml:"favoriteQuote"`
	Signature      dsig.Signature
}

func main() {
	idpCertPath := "samples/sample.pem"

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
}
