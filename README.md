Steps for setting up:

1. Prepare Environment: `echo 1000 > certs/serial; touch certs/index.txt`;
2. Generate server's DH parameters by `./generate-dh-param.sh` if it is not generated yet;
3. Generate client's cert pair by `./generate-client.sh`, modify the CN field for a different CommonName;
4. Generate server's cert pair by `./generate-server.sh`, modify the CN field for a different CommonName.

