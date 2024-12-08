package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

type Reference struct {
	DigestValue string
}

type SignedInfo struct {
	Reference Reference
}

type Signature struct {
	SignedInfo     SignedInfo
	SignatureValue string
}

func (s *Signature) Verify(cert *x509.Certificate) error {
	var assertionWithoutSignature []byte
	var signedInfo []byte

	h := crypto.SHA256.New()
	h.Write(assertionWithoutSignature)

	expectedDigestValue, err := base64.StdEncoding.DecodeString(s.SignedInfo.Reference.DigestValue)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedDigestValue, h.Sum(nil)) {
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

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h.Sum(nil), expectedSignatureValue)
}
