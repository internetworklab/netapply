#!/bin/bash

# Generate client private key
openssl genrsa -out certs/client-key.pem 2048

# Generate client certificate request
openssl req -new -key certs/client-key.pem -out certs/client.csr -subj "/C=US/ST=CA/L=San Francisco/O=MyOrg/CN=vpn-client"

# Sign client certificate
openssl ca -config ./openssl.cnf -extensions client_cert -days 365 -notext -md sha256 -in certs/client.csr -out certs/client-cert.pem -batch

