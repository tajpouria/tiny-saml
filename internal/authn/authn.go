package authn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"text/template"
)

const (
	authnReqTmplPath        = "templates/authn_req.xml"
	authnResAssertTmplPath  = "templates/authn_res_assert.xml"
	authnResSigInfoTmplPath = "templates/authn_res_sig_info.xml"
	authnResSigTmplPath     = "templates/authn_res_sig.xml"
	authnResTmplPath        = "templates/authn_res.xml"
)

type AuthnReqData struct {
	ID           string
	IssueInstant string
}

type Res struct {
	ID           string      `xml:"ID,attr"`
	InResponseTo string      `xml:"InResponseTo,attr"`
	IssueInstant string      `xml:"IssueInstant,attr"`
	Destination  string      `xml:"Destination,attr"`
	StatusCode   string      `xml:"StatusCode,attr"`
	Attributes   []Attribute `xml:"saml:Attribute"`
	Signature    Signature   `xml:"Signature:omitempty"`
}

type Attribute struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"saml:AttributeValue"`
}

type Signature struct {
	DigestValue    string `xml:"ds:DigestValue"`
	SignatureValue string `xml:"ds:SignatureValue"`
}

func CreateAuthnReq(d *AuthnReqData) ([]byte, error) {
	tmpl, err := template.ParseFiles(authnReqTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse authn request template: %v", err)
	}

	var output bytes.Buffer
	err = tmpl.Execute(&output, d)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to execute authn request (w/o signature) template: %v", err)
	}

	return output.Bytes(), nil
}

func (r *Res) GenerateXML(privateKey *rsa.PrivateKey) ([]byte, error) {
	var tmplOutput bytes.Buffer

	// Create the assertion without signature
	tmpl, err := template.ParseFiles(authnResAssertTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse assertion template: %v", err)
	}
	err = tmpl.Execute(&tmplOutput, map[string]any{
		"ID":           r.ID,
		"IssueInstant": r.IssueInstant,
		"Attributes":   r.Attributes,
	})
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to exec assertion template: %v", err)
	}
	assertB := tmplOutput.Bytes()
	tmplOutput.Reset()

	// Calculate the digest of the assertion for signed info
	assertH := crypto.SHA256.New()
	assertH.Write(assertB)
	assertDigestVal := base64.StdEncoding.EncodeToString(assertH.Sum(nil))

	// Create the signed info
	tmpl, err = template.ParseFiles(authnResSigInfoTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse signature info template %v", err)
	}
	err = tmpl.Execute(&tmplOutput, map[string]string{
		"DigestValue": assertDigestVal,
	})
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to exec signature info template %v", err)
	}
	sigInfoB := tmplOutput.Bytes()
	tmplOutput.Reset()

	// Calculate the signature value for the signature
	sigInfoH := crypto.SHA256.New()
	sigInfoH.Write(sigInfoB)
	sigB, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sigInfoH.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("[authn]: SignPKCS1v15 failed: %v", err)
	}
	sigVal := base64.StdEncoding.EncodeToString(sigB)

	// Create the signature
	tmpl, err = template.ParseFiles(authnResSigTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse signature template: %v", err)
	}
	err = tmpl.Execute(&tmplOutput, map[string]string{
		"SignedInfoElement": string(sigInfoB),
		"SignatureValue":    sigVal,
	})
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to exec signature template: %v", err)
	}
	sigB = tmplOutput.Bytes()
	tmplOutput.Reset()

	// Create the assertion with signature
	tmpl, err = template.ParseFiles(authnResAssertTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse assertion template: %v", err)
	}
	err = tmpl.Execute(&tmplOutput, map[string]any{
		"ID":               r.ID,
		"IssueInstant":     r.IssueInstant,
		"SignatureElement": string(sigB),
		"Attributes":       r.Attributes,
	})
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to exec assertion template: %v", err)
	}
	assertB = tmplOutput.Bytes()
	tmplOutput.Reset()

	// Create the authentication response
	tmpl, err = template.ParseFiles(authnResTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse authn response template: %v", err)
	}
	err = tmpl.Execute(&tmplOutput, map[string]string{
		"ID":               r.ID,
		"InResponseTo":     r.InResponseTo,
		"IssueInstant":     r.IssueInstant,
		"Destination":      r.Destination,
		"AssertionElement": string(assertB),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to exec authn response template")
	}
	return tmplOutput.Bytes(), nil
}
