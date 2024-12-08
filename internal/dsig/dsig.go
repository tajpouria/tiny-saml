package dsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
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

func (s *Signature) Verify(assertResB []byte, publicKey *rsa.PublicKey) error {
	assertWithoutSig, signedInfo, err := splitAssertResSig(assertResB)
	if err != nil {
		return fmt.Errorf("[dsig]: Failed to split assertion response signature: %v", err)
	}

	fmt.Println(string(assertWithoutSig), string(signedInfo))

	assertWithoutSigH := crypto.SHA256.New()
	assertWithoutSigH.Write(assertWithoutSig)

	expectedDigestValue, err := base64.StdEncoding.DecodeString(s.SignedInfo.Reference.DigestValue)
	if err != nil {
		return fmt.Errorf("[dsig]: Failed to base64 decode DigestValue: %v", err)
	}

	if !bytes.Equal(expectedDigestValue, assertWithoutSigH.Sum(nil)) {
		// TODO: Notify client that this is 400
		return errors.New("[dsig]: Digest value does not match")
	}

	SignedInfoH := crypto.SHA256.New()
	SignedInfoH.Write(signedInfo)

	expectedSignatureValue, err := base64.StdEncoding.DecodeString(s.SignatureValue)
	if err != nil {
		return fmt.Errorf("[dsig]: Failed to base64 decode SignatureValue: %v", err)
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, SignedInfoH.Sum(nil), expectedSignatureValue)
	if err != nil {
		// TODO: Notify client that this is 400
		return fmt.Errorf("[dsig]: VerifyPKCS1v15 failed to verify the signature: %v", err)
	}

	return nil
}

func (s *Signature) Sign(assertResB []byte, privateKey *rsa.PrivateKey) error {
	_, signedInfo, err := splitAssertResSig(assertResB)
	if err != nil {
		return fmt.Errorf("[dsig]: Failed to split assertion response signature: %v", err)
	}

	sigH := crypto.SHA256.New()
	sigH.Write(signedInfo)

	sigB, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, sigH.Sum(nil))
	if err != nil {
		return fmt.Errorf("[dsig]: SignPKCS1v15 failed: %v", err)
	}

	sigValue := base64.StdEncoding.EncodeToString(sigB)

	fmt.Printf("SignatureValue: %s\n", sigValue)

	return nil
}

func splitAssertResSig(assertResB []byte) ([]byte, []byte, error) {
	assertWithoutSigRe := regexp.MustCompile(`(?s)<Signature.*?</Signature>`)

	assertWithoutSig := assertWithoutSigRe.ReplaceAll(assertResB, []byte(""))

	signedInfoRe := regexp.MustCompile(`(?s)<SignedInfo.*?</SignedInfo>`)

	signedInfo := signedInfoRe.Find(assertResB)
	if signedInfo == nil {
		return nil, nil, fmt.Errorf("[dsig]: no match for SignedInfo")
	}

	return assertWithoutSig, signedInfo, nil
}
