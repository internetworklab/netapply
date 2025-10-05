#!/bin/bash

openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:secp384r1 \
  -keyout certs/client-key.pem \
  -out certs/client-cert.pem \
  -nodes \
  -sha256 \
  -days 365 \
  -subj '/CN=vpn-client' \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=clientAuth" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "subjectAltName=DNS:vpn-client"

openssl x509 -fingerprint -sha256 -in certs/client-cert.pem -noout 
