package authn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"regexp"
	"text/template"
)

const (
	authnReqTmplPath        = "templates/authn_req.xml"
	authnResAssertTmplPath  = "templates/authn_res_assert.xml"
	authnResSigInfoTmplPath = "templates/authn_res_sig_info.xml"
	authnResSigTmplPath     = "templates/authn_res_sig.xml"
	authnResTmplPath        = "templates/authn_res.xml"
)

type Request struct {
	ID                          string `xml:"ID,attr"`
	IssueInstant                string `xml:"IssueInstant,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
}

type Response struct {
	ID             string      `xml:"ID,attr"`
	InResponseTo   string      `xml:"InResponseTo,attr"`
	IssueInstant   string      `xml:"IssueInstant,attr"`
	Destination    string      `xml:"Destination,attr"`
	StatusCode     StatusCode  `xml:"Status>StatusCode"`
	Attributes     []Attribute `xml:"Assertion>AttributeStatement>Attribute"`
	DigestValue    string      `xml:"Assertion>Signature>SignedInfo>Reference>DigestValue"`
	SignatureValue string      `xml:"Assertion>Signature>SignatureValue"`
}

type StatusCode struct {
	Value string `xml:"Value,attr"`
}

type Attribute struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"AttributeValue"`
}

type ErrBadSignature struct {
	Message string
}

func (e *ErrBadSignature) Error() string {
	return e.Message
}

func (r *Request) GenerateXML() ([]byte, error) {
	tmpl, err := template.ParseFiles(authnReqTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse authn request template: %v", err)
	}

	var output bytes.Buffer
	err = tmpl.Execute(&output, r)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to execute authn request (w/o signature) template: %v", err)
	}

	return output.Bytes(), nil
}

func (r *Response) GenerateXML(privateKey *rsa.PrivateKey) ([]byte, error) {
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
	assertB := bytes.TrimSpace(tmplOutput.Bytes())
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
	sigValB := base64.StdEncoding.EncodeToString(sigB)

	// Create the signature
	tmpl, err = template.ParseFiles(authnResSigTmplPath)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to parse signature template: %v", err)
	}
	err = tmpl.Execute(&tmplOutput, map[string]string{
		"SignedInfoElement": string(sigInfoB),
		"SignatureValue":    sigValB,
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
		"StatusCode":       r.StatusCode.Value,
		"AssertionElement": string(assertB),
	})
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to exec authn response template; %v", err)
	}
	return tmplOutput.Bytes(), nil
}

func (r *Response) Verify(authnResB *[]byte, publicKey *rsa.PublicKey) error {
	// Extract the assertion
	assertRe, err := regexp.Compile(`(?s)<Assertion.*?</Assertion>`)
	if err != nil {
		return fmt.Errorf("[authn]: Failed to compile assertion regexp: %v", err)
	}
	assertB := assertRe.Find(*authnResB)
	if assertB == nil {
		return &ErrBadSignature{Message: "assertion is empty"}
	}

	// Extract the signed info
	sigInfoRe, err := regexp.Compile(`(?s)<SignedInfo.*?</SignedInfo>`)
	if err != nil {
		return fmt.Errorf("[authn]: Failed to signed info regexp: %v", err)
	}
	sigInfoB := sigInfoRe.Find(*authnResB)
	if sigInfoB == nil {
		return &ErrBadSignature{Message: "signed info is empty"}
	}

	// Remove the signature from assertion
	sigRe, err := regexp.Compile(`(?s)<Signature.*?</Signature>`)
	if err != nil {
		return fmt.Errorf("[authn]: Failed to compile signature regexp: %v", err)
	}
	assertB = sigRe.ReplaceAll(assertB, []byte(""))
	assertB = bytes.TrimSpace(assertB)

	// Verify the assertion
	digestValB, err := base64.StdEncoding.DecodeString(r.DigestValue)
	if err != nil {
		return &ErrBadSignature{Message: fmt.Sprintf("failed to base64 decode assertion digest value: %v", err)}
	}
	assertH := crypto.SHA256.New()
	assertH.Write(assertB)
	if !bytes.Equal(digestValB, assertH.Sum(nil)) {
		return &ErrBadSignature{Message: "assertion digest does not match the digest value"}
	}

	// Verify the signature value
	sigValB, err := base64.StdEncoding.DecodeString(r.SignatureValue)
	if err != nil {
		return &ErrBadSignature{Message: fmt.Sprintf("failed to base64 decode signature value: %v", err)}
	}
	sigInfoH := crypto.SHA256.New()
	sigInfoH.Write(sigInfoB)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sigInfoH.Sum(nil), sigValB)
	if err != nil {
		return &ErrBadSignature{Message: fmt.Sprintf("failed to verify signature value: %v", err)}
	}

	return nil
}
