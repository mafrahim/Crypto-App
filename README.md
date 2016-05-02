# Crypto-App
Final project for Cryptography class

in this project Crypto++ library was used to the demonstrate how the cryptographic functions would work with Crypto library and we planned to do a comparison with a similar program which used Open SSL library. Since the program is for demonstration and testing purposes, it lacks the file i/o functionality of the primary program. The main.exe would take 32 byte key file and and plain text file as input and run AES encryption on the file which would result in an output of ciphertext, it would then generate a public and private RSA key files and encrypt the the key file using the 1024 bits RSA public key. After encryption is done, it would reverse direction and decrypt the key file using the RSA private key and afterwards decrypt the previously generated ciphertext. 

