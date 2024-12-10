package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tajpouria/tiny-saml/internal/authn"
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
	authnResD := authn.Response{
		ID:           "id",
		InResponseTo: "respond_to_id",
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  "http://localhost:8000/idp",
		StatusCode: authn.StatusCode{
			Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
		},
		Attributes: []authn.Attribute{
			{Name: "Username", Value: "Pouria"},
		},
	}
	authnResB, err := authnResD.GenerateXML(idpPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create authn response: %v", err)
	}

	// Unmarshal authnRes

	var authnRes authn.Response
	err = xml.Unmarshal(authnResB, &authnRes)
	if err != nil {
		log.Fatalf("Failed to XML unmarshal authn response %v", err)
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

	err = authnRes.Verify(&authnResB, idpPublicKey)
	var errAuthnResponse *authn.ErrBadSignature
	if err != nil {
		if errors.As(err, &errAuthnResponse) {
			log.Fatalf("BAD Authn Response: Failed to verify authn response: %v", err)
		}
		log.Fatalf("Failed to verify authn response: %v", err)
	}

	fmt.Println("authn response is valid!")

	mux := http.NewServeMux()
	routes.SPRoutes(mux)
	routes.IDPRoutes(mux)
	fmt.Println("Server running at http://localhost:8000")
	http.ListenAndServe(":8000", mux)
}
