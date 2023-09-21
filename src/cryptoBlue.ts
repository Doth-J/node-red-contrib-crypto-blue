import forge from "node-forge";
import * as NodeRED from "node-red";

interface CipherNodeConfig extends NodeRED.NodeDef{
    function:string,
    algorithm:forge.cipher.Algorithm,
    ivSize:number,
    iv:string,
    keySize:number,
    key:string
}

interface Pkdf2NodeConfig extends NodeRED.NodeDef{
    keySize:string,
    iterations:string,
    salt:string,
    saltSize:string,
    password:string
}

interface PKINodeConfig extends NodeRED.NodeDef{
    function:string,
    privateKey:string,
    privateKeyType:string,
    publicKey:string
    publicKeyType:string,
}

interface HasherNodeConfig extends NodeRED.NodeDef{
    function:string,
    hashSize:string,
    hmacKey:string,
    verification:string,
}

export = function(RED:NodeRED.NodeAPI){

    function CipherNode(this:NodeRED.Node, config:CipherNodeConfig){
      RED.nodes.createNode(this,config);

      function blockCipher(blockCipher:forge.cipher.BlockCipher,iv:string,message:forge.util.ByteStringBuffer){
        blockCipher.start({iv:iv});
        blockCipher.update(message)
        blockCipher.finish();
        return blockCipher.output;
      }

      this.on('input',(msg:any,send,done)=>{
        const options = {
            algorithm: config.algorithm,
            ivSize: config.ivSize,
            keySize: config.keySize,
            iv: msg.iv as string || config.iv,
            key: msg.key as string || config.key
        }
        switch(config.function){
            case "Encrypt":{
                if(options.key == '' && options.iv == ''){
                    const key = forge.random.getBytesSync(options.keySize);
                    const iv = forge.random.getBytesSync(options.ivSize);
                    msg.payload = {
                        iv:forge.util.bytesToHex(iv),
                        key:forge.util.bytesToHex(key),
                        encrypted:blockCipher(
                            forge.cipher.createCipher(options.algorithm,key),
                            iv,
                            forge.util.createBuffer(typeof msg.payload==='string'?msg.payload:JSON.stringify(msg.payload))
                        ).toHex()
                    };
                }else if(options.key== ''){
                    const key = forge.random.getBytesSync(options.keySize);
                    msg.payload = {
                        key:forge.util.bytesToHex(key),
                        encrypted:blockCipher(
                            forge.cipher.createCipher(options.algorithm,key),
                            forge.util.hexToBytes(options.iv),
                            forge.util.createBuffer(typeof msg.payload==='string'?msg.payload:JSON.stringify(msg.payload))
                        ).toHex()
                    };
                }else if(options.iv == ''){
                    const iv = forge.random.getBytesSync(options.ivSize);
                    msg.payload = {
                        iv:forge.util.bytesToHex(iv),
                        encrypted:blockCipher(
                            forge.cipher.createCipher(options.algorithm,forge.util.hexToBytes(options.key)),
                            iv,
                            forge.util.createBuffer(typeof msg.payload==='string'?msg.payload:JSON.stringify(msg.payload))
                        ).toHex()
                    };
                }else{
                    msg.payload = {
                        encrypted:blockCipher(
                            forge.cipher.createCipher(options.algorithm,forge.util.hexToBytes(options.key)),
                            forge.util.hexToBytes(options.iv),
                            forge.util.createBuffer(typeof msg.payload==='string'?msg.payload:JSON.stringify(msg.payload))
                        ).toHex()
                    };
                }
                break;
            }
            case "Decrypt":{
                msg.payload = {
                    decrypted:blockCipher(
                        forge.cipher.createDecipher(options.algorithm,forge.util.hexToBytes(options.key)),
                        forge.util.hexToBytes(options.iv),
                        forge.util.createBuffer(forge.util.hexToBytes(msg.payload))
                    ).toString()
                };
                break;
            }
        }
        send(msg);
        if(done) done();
      });
    }
    RED.nodes.registerType('cipher',CipherNode);

    function Pkdf2Node(this:NodeRED.Node, config:Pkdf2NodeConfig){
        RED.nodes.createNode(this,config);
        this.on('input',(msg:any,send: (arg0: any) => void,done: () => void)=>{
            const options = {
                saltSize: config.saltSize,
                keySize: config.keySize,
                iterations: msg.iterations as string || config.iterations,
                salt:msg.salt as string || config.salt,
                password:msg.password as string || config.password,
            }
            msg.payload = {}
            if(options.salt == ''){
                options.salt = forge.random.getBytesSync(parseInt(options.saltSize));
                msg.payload.salt = forge.util.bytesToHex(options.salt);
            }else{
                options.salt = forge.util.hexToBytes(options.salt);
            }
            msg.payload.key = forge.util.bytesToHex(forge.pkcs5.pbkdf2(options.password,options.salt,parseInt(options.iterations),parseInt(options.keySize)))
            send(msg);
            if(done) done();
        })
    }
    RED.nodes.registerType('pkdf',Pkdf2Node);

    function PKINode(this:NodeRED.Node, config:PKINodeConfig){
        RED.nodes.createNode(this,config);
        const pki = forge.pki;
        this.on('input',(msg:any,send,done)=>{
            let options:any = {
                function: msg.function as string || config.function,
            }
            switch(config.privateKeyType){
                case "str":{
                    options.privateKey = msg.privateKey as string || config.privateKey
                    break;
                }
                case "msg":{
                    options.privateKey = msg[config.privateKey] as string
                    break;
                }
                case "env":{
                    options.privateKey= process.env[msg.publicKey] as string
                    break;
                }
            }
            switch(config.publicKeyType){
                case "str":{
                    options.publicKey = msg.publicKey as string || config.publicKey
                    break;
                }
                case "msg":{
                    options.publicKey = msg[config.publicKey] as string
                    break;
                }
                case "env":{
                    options.publicKey= process.env[msg.publicKey] as string
                    break;
                }
            }
            switch(options.function){
                case "generate":{
                    const keys = pki.ed25519.generateKeyPair();
                    msg.payload = {
                        privateKey: forge.util.binary.hex.encode(keys.privateKey),
                        publicKey:forge.util.binary.hex.encode(keys.publicKey)
                    }
                    break;
                }
                case "sign":{
                    const md = forge.md.sha256.create();
                    md.update(typeof msg.payload =="string" ? msg.payload : JSON.stringify(msg.payload));
                    const privateKey = forge.util.createBuffer(Buffer.from(options.privateKey,'hex'));
                    msg.payload = {
                        message: msg.payload,
                        signature: forge.util.binary.hex.encode(pki.ed25519.sign({
                            message:md.digest(),
                            privateKey:privateKey
                        }))
                    }
                    break;
                }
                case "verify":{
                    const md = forge.md.sha256.create();
                    md.update(typeof msg.payload =="string" ? msg.payload : JSON.stringify(msg.payload));
                    const publicKey = forge.util.createBuffer(Buffer.from(options.publicKey,'hex'));
                    const signature = forge.util.createBuffer(Buffer.from(msg.signature,'hex'));
                    msg.payload = {
                        message: msg.payload,
                        verification: pki.ed25519.verify({
                            message:md.digest(),
                            signature:signature,
                            publicKey:publicKey
                        })
                    }
                    break;
                }
            }
            send(msg);
            if(done) done();
        })
    }
    RED.nodes.registerType('pki',PKINode);
    
    function HasherNode(this:NodeRED.Node, config:HasherNodeConfig){
        RED.nodes.createNode(this,config);
        this.on('input',(msg:any,send,done)=>{
            const options = {
                hashSize: config.hashSize,
                hmacKey: msg.hmacKey as string || config.hmacKey,
                verification: msg.verification as string || config.verification
            }
            const message = typeof msg.payload == 'string' ? msg.payload:JSON.stringify(msg.payload);
            switch(config.function){
                case "Generate Hash":{
                    const digest = forge.md;
                    switch(options.hashSize){
                        case "SHA256":{
                            msg.payload = digest.sha256.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA384":{
                            msg.payload = digest.sha384.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA512":{
                            msg.payload = digest.sha512.create().update(message).digest().toHex();
                            break;
                        }
                    }
                    break;
                }
                case "Generate HMAC":{
                    const hmac = forge.hmac.create();
                    switch(options.hashSize){
                        case "SHA256":{
                            hmac.start('sha256',options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA384":{
                            hmac.start('sha384',options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA512":{
                            hmac.start('sha512',options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                    }
                    msg.payload = hmac.digest().toHex();    
                    break;
                }
                case "Verify Hash":{
                    const digest = forge.md;
                    let hashToverify;
                    switch(options.hashSize){
                        case "SHA256":{
                            hashToverify = digest.sha256.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA384":{
                            hashToverify = digest.sha384.create().update(message).digest().toHex();
                            break;
                        }
                        case "SHA512":{
                            hashToverify = digest.sha512.create().update(message).digest().toHex();
                            break;
                        }
                    }
                    msg.payload = {verification:hashToverify == options.verification};
                    break;
                }
                case "Verify HMAC":{
                    const hmac = forge.hmac.create();
                    switch(options.hashSize){
                        case "SHA256":{
                            hmac.start('sha256',options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA384":{
                            hmac.start('sha384',options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                        case "SHA512":{
                            hmac.start('sha512',options.hmacKey);
                            hmac.update(message);
                            break;
                        }
                    }
                    msg.payload = {verification: hmac.digest().toHex() == options.verification}
                    break;
                }
            }
            send(msg);
            if(done) done();
        })
    }
    RED.nodes.registerType('hasher',HasherNode);
}