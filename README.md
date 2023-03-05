# Crypto Blue :blue_book:
A collection of Node-RED nodes for crypto utilities using the [node-forge](https://www.npmjs.com/package/node-forge) module.

## Installation :zap:
To install the collection execute the following command inside the `./.node-red` directory:
```console
npm install node-red-contrib-crypto-blue
```
## Node Included :package:
The collection is comprised of the following nodes, alognside the utilites provided by each one:
- `PKDF`: Node utilizing a Password Key Derivation Function for generating and recreating encryption keys.
- `Hasher`: Node utilizin the SHA algorithm for generating hashes, hmac from payloads as well as verifying hashes.
- `Cipher`: Node utilizing AES algorithm for encryption and decryption of payloads.
- `PKI`: Node utiliing the Ed25519 curve for generating key-pairs, signing payloads and verifying signatures.
