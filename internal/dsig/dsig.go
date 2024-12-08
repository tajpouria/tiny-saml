package dsig

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

type Reference struct {
	DigestValue string `xml:""`
}

type SignedInfo struct {
	Reference Reference
}

type Signature struct {
	SignedInfo     SignedInfo
	SignatureValue string
}

func (s *Signature) Verify(assertResContent []byte, cert *x509.Certificate) error {
	assertWithoutSig, signedInfo, err := splitAssertResContentSig(assertResContent)
	if err != nil {
		return err
	}

	fmt.Println(string(assertWithoutSig), string(signedInfo))

	h := crypto.SHA256.New()
	h.Write(assertWithoutSig)

	expectedDigestValue, err := base64.StdEncoding.DecodeString(s.SignedInfo.Reference.DigestValue)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedDigestValue, h.Sum(nil)) {
		// TODO: Notify client that this is 400
		return errors.New("[dsig]: Digest value does not match")
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("[dsig]: Public must be *rsa.PublicKey")
	}

	h = crypto.SHA256.New()
	h.Write(signedInfo)

	expectedSignatureValue, err := base64.StdEncoding.DecodeString(s.SignatureValue)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h.Sum(nil), expectedSignatureValue)
	if err != nil {
		// TODO: Notify client that this is 400
		return err
	}

	return nil
}

func splitAssertResContentSig(assertResContent []byte) ([]byte, []byte, error) {
	assertWithoutSigRe := regexp.MustCompile(`(?s)<Signature.*?</Signature>`)

	assertWithoutSig := assertWithoutSigRe.ReplaceAll(assertResContent, []byte(""))

	signedInfoRe := regexp.MustCompile(`(?s)<SignedInfo.*?</SignedInfo>`)

	signedInfo := signedInfoRe.Find(assertResContent)
	if signedInfo == nil {
		return nil, nil, fmt.Errorf("[dsig]: no match for SignedInfo")
	}

	return assertWithoutSig, signedInfo, nil
}
