#!/bin/bash

openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:secp384r1 \
  -keyout certs/server-key.pem \
  -out certs/server-cert.pem \
  -nodes \
  -sha256 \
  -days 365 \
  -subj '/CN=vpn-server'

openssl x509 -fingerprint -sha256 -in certs/server-cert.pem -noout 
