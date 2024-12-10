package routes

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/tajpouria/tiny-saml/internal/authn"
)

const (
	samlInitTmpl = "templates/sp_home.html"
)

func SPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/sp", homeHandler)
	mux.HandleFunc("/sp/saml/init", samlInitHandler)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, samlInitTmpl)
}

func samlInitHandler(w http.ResponseWriter, r *http.Request) {
	// Generate authn request
	authnReq := authn.Request{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
	}
	authnReqB, err := authnReq.GenerateXML()
	if err != nil {
		http.Error(w, "Failed to generate authn request", http.StatusInternalServerError)
		log.Printf("Failed to generate authn request XML: %v", err)
	}

	// Compress the authn request
	var flateOutput bytes.Buffer
	fw, err := flate.NewWriter(&flateOutput, 2)
	if err != nil {
		http.Error(w, "Failed to generate authn request", http.StatusInternalServerError)
		log.Printf("Failed to initial flate writer: %v", err)
	}
	_, err = fw.Write(authnReqB)
	if err != nil {
		http.Error(w, "Failed to generate authn request", http.StatusInternalServerError)
		log.Printf("Failed to the request to flate writer %v", err)
	}
	err = fw.Close()
	if err != nil {
		log.Printf("Failed to close the flate writer: %v", err)
	}
	authnReqB = flateOutput.Bytes()

	// Base64 encode the authn request
	authnReqS := base64.StdEncoding.EncodeToString(authnReqB)

	// Redirect to idP SSO endpoint with authn request
	ssoURL := fmt.Sprintf("http://localhost:8000/idp/sso?SAMLRequest=%s", authnReqS)
	http.Redirect(w, r, ssoURL, http.StatusFound)
}
