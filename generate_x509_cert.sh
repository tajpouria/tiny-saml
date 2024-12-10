#!/bin/bash

outputDir="samples"

mkdir -p "$outputDir"

# Generate the RSA private key in PKCS#1 format
openssl genrsa -traditional -out "$outputDir/private_key.pem" 2048

# Create a CSR
openssl req -new -key "$outputDir/private_key.pem" -out "$outputDir/certificate.csr" -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=tajpouria.com"

# Generate a self-signed X.509 certificate
openssl x509 -req -days 365 -in "$outputDir/certificate.csr" -signkey "$outputDir/private_key.pem" -out "$outputDir/certificate.pem"

rm "$outputDir/certificate.csr"

echo "X.509 Certificate and private key (in PKCS#1 format) have been generated in the '$outputDir' directory."
