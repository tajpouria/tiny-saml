package routes

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/tajpouria/tiny-saml/internal/authn"
)

const (
	samlInitTmplPath = "templates/sp_home.html"
	samlACTmplPath   = "templates/sp_ac.html"
)

var idpPublicKey *rsa.PublicKey

func InitSP(mux *http.ServeMux, key *rsa.PublicKey) {
	idpPublicKey = key
	mux.HandleFunc("/sp", homeHandler)
	mux.HandleFunc("/sp/saml/init", samlInitHandler)
	mux.HandleFunc("/sp/saml/ac", samlACHandler)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, samlInitTmplPath)
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

	// Compress authn request
	var flateOutput bytes.Buffer
	fw, err := flate.NewWriter(&flateOutput, 2)
	if err != nil {
		http.Error(w, "Failed to generate authn request", http.StatusInternalServerError)
		log.Printf("Failed to init flate writer: %v", err)
	}
	_, err = fw.Write(authnReqB)
	if err != nil {
		http.Error(w, "Failed to generate authn request", http.StatusInternalServerError)
		log.Printf("Failed to the request to flate writer %v", err)
	}
	err = fw.Close()
	if err != nil {
		http.Error(w, "Failed to finalize compression", http.StatusInternalServerError)
		log.Printf("Failed to close flate writer: %v", err)
		return
	}
	authnReqB = flateOutput.Bytes()

	// Base64 encode authn request
	authnReqS := base64.URLEncoding.EncodeToString(authnReqB)

	// Redirect to identity provider SSO endpoint with authn request
	ssoURL := fmt.Sprintf("http://localhost:8000/idp/sso?SAMLRequest=%s", authnReqS)
	http.Redirect(w, r, ssoURL, http.StatusFound)
}

func samlACHandler(w http.ResponseWriter, r *http.Request) {
	// Basic validation
	authnResS := r.URL.Query().Get("SAMLResponse")
	if authnResS == "" {
		http.Error(w, "Auth response is required", http.StatusBadRequest)
		return
	}

	// Base64 decode authn response
	authnResB, err := base64.URLEncoding.DecodeString(authnResS)
	if err != nil {
		http.Error(w, "Invalid authn response encoding", http.StatusBadRequest)
		log.Printf("Failed to base64 decode authn response: %v", err)
		return
	}

	// Decompress authn response
	fr := flate.NewReader(bytes.NewReader(authnResB))
	var flateOutput bytes.Buffer
	_, err = io.Copy(&flateOutput, fr)
	defer func() {
		err := fr.Close()
		if err != nil {
			log.Printf("Failed to close flate reader: %v", err)
		}
	}()
	if err != nil {
		http.Error(w, "Invalid authn response compression", http.StatusBadRequest)
		log.Printf("Failed to copy from flate reader to output: %v", err)
		return
	}
	authnResB = flateOutput.Bytes()

	// Validate authn response
	var authnRes authn.Response
	err = xml.Unmarshal(authnResB, &authnRes)
	if err != nil {
		http.Error(w, "Invalid authn response format", http.StatusBadRequest)
		log.Printf("Failed to unmarshal authn response: %v", err)
		return
	}
	err = authnRes.Verify(&authnResB, idpPublicKey)
	if err != nil {
		http.Error(w, "Invalid auth response signature", http.StatusBadRequest)
		log.Printf("Failed to verify auth response: %v", err)
		return
	}

	// Proceed with authn
	tmpl, err := template.ParseFiles(samlACTmplPath)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
	var tmplOutput bytes.Buffer
	tmpl.Execute(&tmplOutput, map[string]any{
		"StatusCode": authnRes.StatusCode.Value,
		"Attributes": authnRes.Attributes,
	})
	w.Header().Set("Content-Type", "text/html")
	w.Write(tmplOutput.Bytes())
}
