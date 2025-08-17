Statistics api


# Private key and public key generation
openssl rsa -in private_key.pem -inform pem -RSAPublicKey_out -outform DER -out public_key.der