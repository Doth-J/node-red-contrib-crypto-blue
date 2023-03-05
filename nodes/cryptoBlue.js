"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
const node_forge_1 = __importDefault(require("node-forge"));
module.exports = function (RED) {
    function CipherNode(config) {
        RED.nodes.createNode(this, config);
        function blockCipher(blockCipher, iv, message) {
            blockCipher.start({ iv: iv });
            blockCipher.update(message);
            blockCipher.finish();
            return blockCipher.output;
        }
        this.on('input', (msg, send, done) => {
            const options = {
                algorithm: config.algorithm,
                ivSize: config.ivSize,
                keySize: config.keySize,
                iv: msg.iv || config.iv,
                key: msg.key || config.key
            };
            switch (config.function) {
                case "Encrypt": {
                    if (options.key == '' && options.iv == '') {
                        const key = node_forge_1.default.random.getBytesSync(options.keySize);
                        const iv = node_forge_1.default.random.getBytesSync(options.ivSize);
                        msg.payload = {
                            iv: node_forge_1.default.util.bytesToHex(iv),
                            key: node_forge_1.default.util.bytesToHex(key),
                            encrypted: blockCipher(node_forge_1.default.cipher.createCipher(options.algorithm, key), iv, node_forge_1.default.util.createBuffer(typeof msg.payload === 'string' ? msg.payload : JSON.stringify(msg.payload))).toHex()
                        };
                    }
                    else if (options.key == '') {
                        const key = node_forge_1.default.random.getBytesSync(options.keySize);
                        msg.payload = {
                            key: node_forge_1.default.util.bytesToHex(key),
                            encrypted: blockCipher(node_forge_1.default.cipher.createCipher(options.algorithm, key), node_forge_1.default.util.hexToBytes(options.iv), node_forge_1.default.util.createBuffer(typeof msg.payload === 'string' ? msg.payload : JSON.stringify(msg.payload))).toHex()
                        };
                    }
                    else if (options.iv == '') {
                        const iv = node_forge_1.default.random.getBytesSync(options.ivSize);
                        msg.payload = {
                            iv: node_forge_1.default.util.bytesToHex(iv),
                            encrypted: blockCipher(node_forge_1.default.cipher.createCipher(options.algorithm, node_forge_1.default.util.hexToBytes(options.key)), iv, node_forge_1.default.util.createBuffer(typeof msg.payload === 'string' ? msg.payload : JSON.stringify(msg.payload))).toHex()
                        };
                    }
                    else {
                        msg.payload = {
                            encrypted: blockCipher(node_forge_1.default.cipher.createCipher(options.algorithm, node_forge_1.default.util.hexToBytes(options.key)), node_forge_1.default.util.hexToBytes(options.iv), node_forge_1.default.util.createBuffer(typeof msg.payload === 'string' ? msg.payload : JSON.stringify(msg.payload))).toHex()
                        };
                    }
                    break;
                }
                case "Decrypt": {
                    msg.payload = {
                        decrypted: blockCipher(node_forge_1.default.cipher.createDecipher(options.algorithm, node_forge_1.default.util.hexToBytes(options.key)), node_forge_1.default.util.hexToBytes(options.iv), node_forge_1.default.util.createBuffer(node_forge_1.default.util.hexToBytes(msg.payload))).toString()
                    };
                    break;
                }
            }
            send(msg);
            if (done)
                done();
        });
    }
    RED.nodes.registerType('cipher', CipherNode);
    function Pkdf2Node(config) {
        RED.nodes.createNode(this, config);
        this.on('input', (msg, send, done) => {
            const options = {
                saltSize: config.saltSize,
                keySize: config.keySize,
                iterations: msg.iterations || config.iterations,
                salt: msg.salt || config.salt,
                password: msg.password || config.password,
            };
            msg.payload = {};
            if (options.salt == '') {
                options.salt = node_forge_1.default.random.getBytesSync(parseInt(options.saltSize));
                msg.payload.salt = node_forge_1.default.util.bytesToHex(options.salt);
            }
            else {
                options.salt = node_forge_1.default.util.hexToBytes(options.salt);
            }
            msg.payload.key = node_forge_1.default.util.bytesToHex(node_forge_1.default.pkcs5.pbkdf2(options.password, options.salt, parseInt(options.iterations), parseInt(options.keySize)));
            send(msg);
            if (done)
                done();
        });
    }
    RED.nodes.registerType('pkdf', Pkdf2Node);
    function PKINode(config) {
        RED.nodes.createNode(this, config);
        const pki = node_forge_1.default.pki;
        this.on('input', (msg, send, done) => {
            const options = {
                privateKey: msg.privateKey || config.privateKey,
                publicKey: msg.publicKey || config.publicKey
            };
            switch (config.function) {
                case "Generate Keys": {
                    const keys = pki.ed25519.generateKeyPair();
                    msg.payload = {
                        privateKey: node_forge_1.default.util.binary.hex.encode(keys.privateKey),
                        publicKey: node_forge_1.default.util.binary.hex.encode(keys.publicKey)
                    };
                    break;
                }
                case "Sign Payload": {
                    const md = node_forge_1.default.md.sha256.create();
                    md.update(typeof msg.payload == "string" ? msg.payload : JSON.stringify(msg.payload));
                    const privateKey = node_forge_1.default.util.createBuffer(Buffer.from(options.privateKey, 'hex'));
                    msg.payload = {
                        message: msg.payload,
                        signature: node_forge_1.default.util.binary.hex.encode(pki.ed25519.sign({
                            message: md.digest(),
                            privateKey: privateKey
                        }))
                    };
                    break;
                }
                case "Verify Signature": {
                    const md = node_forge_1.default.md.sha256.create();
                    md.update(typeof msg.payload.message == "string" ? msg.payload.message : JSON.stringify(msg.payload.message));
                    const publicKey = node_forge_1.default.util.createBuffer(Buffer.from(options.publicKey, 'hex'));
                    const signature = node_forge_1.default.util.createBuffer(Buffer.from(msg.payload.signature, 'hex'));
                    msg.payload = {
                        verification: pki.ed25519.verify({
                            message: md.digest(),
                            signature: signature,
                            publicKey: publicKey
                        })
                    };
                    break;
                }
            }
            send(msg);
            if (done)
                done();
        });
    }
    RED.nodes.registerType('pki', PKINode);
    function HasherNode(config) {
        RED.nodes.createNode(this, config);
        this.on('input', (msg, send, done) => {
            const options = {
                hashSize: config.hashSize,
                hmacKey: msg.hmacKey || config.hmacKey,
                verification: msg.verification || config.verification
            };
            const message = typeof msg.payload == 'string' ? msg.payload : JSON.stringify(msg.payload);
            switch (config.function) {
                case "Generate Hash": {
                    const digest = node_forge_1.default.md;
                    switch (options.hashSize) {
                        case "SHA256": {
                            msg.payload = digest.sha256.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA384": {
                            msg.payload = digest.sha384.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA512": {
                            msg.payload = digest.sha512.create().update(message).digest().toHex();
                            break;
                        }
                    }
                    break;
                }
                case "Generate HMAC": {
                    const hmac = node_forge_1.default.hmac.create();
                    switch (options.hashSize) {
                        case "SHA256": {
                            hmac.start('sha256', options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA384": {
                            hmac.start('sha384', options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA512": {
                            hmac.start('sha512', options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                    }
                    msg.payload = hmac.digest().toHex();
                    break;
                }
                case "Verify Hash": {
                    const digest = node_forge_1.default.md;
                    let hashToverify;
                    switch (options.hashSize) {
                        case "SHA256": {
                            hashToverify = digest.sha256.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA384": {
                            hashToverify = digest.sha384.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA512": {
                            hashToverify = digest.sha512.create().update(message).digest().toHex();
                            break;
                        }
                    }
                    msg.payload = { verification: hashToverify == options.verification };
                    break;
                }
                case "Verify HMAC": {
                    const hmac = node_forge_1.default.hmac.create();
                    switch (options.hashSize) {
                        case "SHA256": {
                            hmac.start('sha256', options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA384": {
                            hmac.start('sha384', options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA512": {
                            hmac.start('sha512', options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                    }
                    msg.payload = { verification: hmac.digest().toHex() == options.verification };
                    break;
                }
            }
            send(msg);
            if (done)
                done();
        });
    }
    RED.nodes.registerType('hasher', HasherNode);
};
