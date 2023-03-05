# Crypto Blue :blue_book:
A collection of Node-RED nodes for crypto utilities using the [node-forge](https://www.npmjs.com/package/node-forge) module.

## Installation :zap:
To install the collection execute the following command inside the `./.node-red` directory:
```console
npm install node-red-contrib-crypto-blue
```
## Node Included :package:
The collection is comprised of the following nodes, alognside the utilites provided by each one:
- [`PKDF`](https://gist.github.com/Doth-J/63f3e0109c4406a5728cc68baa213073): Node utilizing a Password Key Derivation Function for generating and recreating encryption keys.
- [`Hasher`](https://gist.github.com/Doth-J/f4aa68d3d9bcbf3fe9cd2b1b0ee2ef84): Node utilizin the SHA algorithm for generating hashes, hmac from payloads as well as verifying hashes.
- [`Cipher`](https://gist.github.com/Doth-J/da771085e40230a25d37d836ffd13ac4): Node utilizing AES algorithm for encryption and decryption of payloads.
- [`PKI`](https://gist.github.com/Doth-J/a2cf438233bd8b5754b0b259dca4a221): Node utiliing the Ed25519 curve for generating key-pairs, signing payloads and verifying signatures.
