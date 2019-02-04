const {PRE, Delegator, Delegatee, Proxy} = require("./PRE");
const AES = require("./AES")
const param_g = 'abc';
const param_h = 'abc';


const pre = new PRE();

pre.init(param_g, param_h).then(() => {
    const A = new Delegator(pre);
    const B = new Delegatee(pre);

    const plain = "This is test";
    const key = AES.randomKeyGen();
    //A encrypt plain with key in AES256
    const aesEncrypted = AES.encrypt(plain, key);
    //A encrypts key to preEncryptedKey and upload with aesEncrypted to cloud
    const preEncryptedKey = A.encrypt(key);
    //A can download it from cloud and decrypt it at any time
    const preDecryptedKey = A.decrypt(preEncryptedKey);
    const aesDeCryptedFromA = AES.decrypt(aesEncrypted, preDecryptedKey);
    //A generates reKey with B's public key and pass it to Proxy
    const reKeyAB = A.reKeyGen(B.pk);
    //When B requests to download, Proxy reEncrypts what's on the cloud  with reKey
    const reEncryptedKey = Proxy.reEncrypt(preEncryptedKey, reKeyAB);
    //B can decrypted it with his secret key
    const reDecrypted = B.reDecrypt(reEncryptedKey);
    const aesDeCryptedFromB = AES.decrypt(aesEncrypted, reDecrypted);

    //the result are the same
    console.log(aesDeCryptedFromA);
    console.log(aesDeCryptedFromB);

})