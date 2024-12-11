package routes

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/tajpouria/tiny-saml/internal/authn"
)

const (
	idpSSOPath = "templates/idp_sso.html"
	idpPkPath  = "samples/private_key.pem"
)

var idpPrivateKey *rsa.PrivateKey

type LogonRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	AuthnReqS string `json:"samlRequest"`
}

func InitIDP(mux *http.ServeMux, key *rsa.PrivateKey) {
	idpPrivateKey = key
	mux.HandleFunc("/idp/sso", ssoHandler)
	mux.HandleFunc("/idp/sso/logon", ssoLoginHandler)
}

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, idpSSOPath)
}

func ssoLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Basic validation (arbitrary authn)
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var logonRequest LogonRequest
	err := json.NewDecoder(r.Body).Decode(&logonRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode request body: %v", err)
		return
	}
	username, password, authnReqS :=
		strings.TrimSpace(logonRequest.Username),
		strings.TrimSpace(logonRequest.Password),
		strings.TrimSpace(logonRequest.AuthnReqS)
	if username == "" || password == "" || authnReqS == "" {
		http.Error(
			w,
			"Invalid request body (username, password and samlRequest are required)",
			http.StatusBadRequest,
		)
		return
	}

	// Base64 decode authn request
	authReqB, err := base64.URLEncoding.DecodeString(authnReqS)
	if err != nil {
		http.Error(w, "Failed to base64 decode authn request", http.StatusBadRequest)
		log.Printf("Failed to base64 decode authn req: %v", err)
		return
	}

	// Decompress authn request
	fr := flate.NewReader(bytes.NewReader(authReqB))
	defer func() {
		err = fr.Close()
		if err != nil {
			log.Printf("Failed to close the flate reader: %v", err)
		}
	}()
	var flateOutput bytes.Buffer
	_, err = io.Copy(&flateOutput, fr)
	if err != nil {
		http.Error(w, "Failed to flate decompress authn, request", http.StatusBadRequest)
		log.Printf("Failed to copy from flate reader to output: %v", err)
		return
	}
	authReqB = flateOutput.Bytes()
	flateOutput.Reset()

	// Unmarshal and validate authn request
	var authnReq authn.Request
	err = xml.Unmarshal(authReqB, &authnReq)
	if err != nil {
		http.Error(w, "Failed read authn request properties", http.StatusBadRequest)
		log.Printf("Failed to unmarshal authn request %v", err)
		return
	}
	inResponseTo, acURL :=
		strings.TrimSpace(authnReq.ID),
		strings.TrimSpace(authnReq.AssertionConsumerServiceURL)
	if inResponseTo == "" || acURL == "" {
		http.Error(w, "Insufficient data in authn request", http.StatusBadRequest)
		return
	}

	// Create authn response
	authnRes := authn.Response{
		ID:           fmt.Sprintf("%d", time.Now().UnixNano()),
		InResponseTo: inResponseTo,
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  acURL,
		StatusCode: authn.StatusCode{
			Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
		},
		Attributes: []authn.Attribute{
			{Name: "Username", Value: username},
		},
	}
	authnResB, err := authnRes.GenerateXML(idpPrivateKey)
	if err != nil {
		http.Error(w, "Failed to generate authn response", http.StatusInternalServerError)
		log.Printf("Failed to generate authn response XML: %v", err)
		return
	}

	// Compress the authn response
	fw, err := flate.NewWriter(&flateOutput, 2)
	if err != nil {
		http.Error(w, "Failed to generate authn response", http.StatusInternalServerError)
		log.Printf("Failed to init flate writer: %v", err)
		return
	}
	_, err = fw.Write(authnResB)
	if err != nil {
		http.Error(w, "Failed to generate authn response", http.StatusInternalServerError)
		log.Printf("Failed to write the response to flate writer: %v", err)
		return
	}
	err = fw.Close()
	if err != nil {
		http.Error(w, "Failed to finalize compression", http.StatusInternalServerError)
		log.Printf("Failed to close flate writer: %v", err)
		return
	}
	authnResB = flateOutput.Bytes()

	// Base64 encode the authn response
	authnResS := base64.URLEncoding.EncodeToString(authnResB)

	// Redirect to service provider assertion consumer URL with authn response
	acURL = fmt.Sprintf("%s?SAMLResponse=%s", acURL, authnResS)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(acURL))
}
