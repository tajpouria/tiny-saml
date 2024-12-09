package authn

import (
	"bytes"
	"fmt"
	"html/template"
)

const (
	authnReqPath = "templates/authn_req.xml"
	authnResPath = "templates/authn_res.xml"
)

type AuthnReqData struct {
	ID           string
	IssueInstant string
}

type AuthnResData struct {
	ID           string
	InResponseTo string
	IssueInstant string
	Destination  string
	Name         string
	Email        string
}

func CreateAuthnReq(d *AuthnReqData) ([]byte, error) {
	tmpl, err := template.ParseFiles(authnReqPath)
	if err != nil {
		return nil, fmt.Errorf("[autn]: Failed to parse authn request template: %v\n", err)
	}

	var output bytes.Buffer
	err = tmpl.Execute(&output, d)
	if err != nil {
		return nil, fmt.Errorf("[authn]: Failed to execute authn request template: %v\n", err)
	}

	return output.Bytes(), nil
}

func CreateAuthnRes(d *AuthnResData) ([]byte, error) {
	tmpl, err := template.ParseFiles(authnResPath)
	if err != nil {
		return nil, fmt.Errorf("[autn]: Failed to parse authn response template: %v\n", err)
	}

	var output bytes.Buffer
	err = tmpl.Execute(&output, d)
	if err != nil {
		return nil, fmt.Errorf("[autn]: Failed to exec authn response template: %v\n", err)
	}

	return output.Bytes(), nil
}
