#!/bin/bash

# Generate server private key
openssl genrsa -out certs/server-key.pem 2048

# Generate server certificate request
openssl req -new -key certs/server-key.pem -out certs/server.csr -subj "/C=US/ST=CA/L=San Francisco/O=MyOrg/CN=vpn-server"

# Sign server certificate
openssl ca -config ./openssl.cnf -extensions server_cert -days 365 -notext -md sha256 -in certs/server.csr -out certs/server-cert.pem -batch
