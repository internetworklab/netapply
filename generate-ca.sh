# Generate CA private key
openssl genrsa -out certs/ca-key.pem 2048

# Generate CA certificate
openssl req -new -x509 -days 3650 -key certs/ca-key.pem -out certs/ca-cert.pem -subj "/C=US/ST=CA/L=San Francisco/O=MyOrg/CN=MyCA"

