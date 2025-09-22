#!/bin/bash

openssl req -x509 -newkey ec \
  -keyout certs/server-key.pem \
  -out certs/server-cert.pem \
  -nodes \
  -sha256 \
  -days 365 \
  -subj '/CN=vpn-server' \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "subjectAltName=DNS:vpn-server"

openssl x509 -fingerprint -sha256 -in certs/server-cert.pem -noout 
