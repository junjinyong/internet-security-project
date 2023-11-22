rm cert.crl
gcc sampleClient.c -o sampleClient -lssl -lcrypto -lcurl
