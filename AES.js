const crypto = require('crypto');

class AES {
    static get IVLEN() {
        return 16
    }

    static get KEYLEN() {
        return 32
    }

    static get MODE() {
        return 'aes-256-cbc'
    }

    /**
     *
     * @returns {string} hex string with KEYLEN
     */
    static randomKeyGen() {
        return crypto.randomBytes(AES.KEYLEN).toString('hex')
    }

    /**
     *
     * @param {string} plain - plain text to be encrypted
     * @param {string} key - hex string of key with length 64
     * @returns {string} iv|encrypted
     */
    static encrypt(plain, key) {
        let iv = crypto.randomBytes(AES.IVLEN);
        let cipher = crypto.createCipheriv(AES.MODE, new Buffer.from(key, 'hex'), iv);
        let encrypted = cipher.update(plain);

        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + encrypted.toString('hex');
    }

    /**
     *
     * @param {string} encrypted - iv/encrypted
     * @param {string} key - hex string of key with length 64
     * @returns {String} decrypted
     */
    static decrypt(encrypted, key) {
        let buffer = new Buffer.from(encrypted, 'hex');
        let iv = buffer.slice(0, AES.IVLEN);
        let encryptedText = buffer.slice(AES.IVLEN);
        let decipher = crypto.createDecipheriv(AES.MODE, new Buffer.from(key, 'hex'), iv);
        let decrypted = decipher.update(encryptedText);

        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }
}


//let encrypted = AES.encrypt('263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3', '263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3')
//console.log(encrypted)
//let decrypted = AES.decrypt(encrypted, '263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3')
//console.log(decrypted)

module.exports = AES;
