package routes

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/tajpouria/tiny-saml/internal/authn"
)

const (
	idpSSOPath = "templates/idp_sso.html"
)

func IDPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/idp/sso", ssoHandler)
	mux.HandleFunc("/idp/sso/logon", ssoLoginHandler)
}

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, idpSSOPath)
}

func ssoLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Basic authn validation (arbitrary authn)
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Unable to parse form data", http.StatusBadRequest)
		log.Printf("Failed to parse the form data: %v", err)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	authReqS := strings.TrimSpace(r.FormValue("SAMLRequest"))
	if username == "" || password == "" || authReqS == "" {
		fmt.Printf("%s, %s, %s", username, password, authReqS)
		http.Error(
			w,
			"Invalid form data (username, password and SAMLRequest are required)",
			http.StatusBadRequest,
		)
		return
	}

	// Base64 decode authn request
	authReqB, err := base64.StdEncoding.DecodeString(authReqS)
	if err != nil {
		http.Error(w, "Failed to base64 decode authn request", http.StatusBadRequest)
		log.Printf("Failed to base64 decode authn req: %v", err)
		return
	}

	// Decompress authn request
	fr := flate.NewReader(bytes.NewReader(authReqB))
	var flateOutput bytes.Buffer
	_, err = io.Copy(&flateOutput, fr)
	if err != nil {
		http.Error(w, "Failed to flate decompress authn, request", http.StatusBadRequest)
		log.Printf("Failed to copy from flate reader to output: %v", err)
		return
	}
	err = fr.Close()
	if err != nil {
		log.Printf("Failed to close the flare reader: %v", err)
	}
	authReqB = flateOutput.Bytes()

	// Unmarshal authn request
	var authnReq authn.Request
	err = xml.Unmarshal(authReqB, &authnReq)
	if err != nil {
		http.Error(w, "Failed read authn request properties", http.StatusBadRequest)
		log.Printf("Failed to unmarshal authn request %v", err)
		return
	}

	fmt.Println("%+v", authnReq)
}
