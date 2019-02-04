const mcl = require('mcl-wasm');


class PRE {
    /**
     * Init global parameters
     * @param {string} g - global parameter to create generator of G1
     * @param {string} h - global parameter to create generator of G2
     * @returns {Promise<void>}
     */
    async init(g, h) {
        await mcl.init(mcl.BN462);
        this.g = new mcl.G1();
        this.g.setHashOf(g);

        this.h = new mcl.G2();
        this.h.setHashOf(h);

    }

    /**
     * Generate key pairs in G1
     * @returns  {[Object, Object]} - [secret key, public key]
     */
    keyGenInG1() {
        const ska = new mcl.Fr();
        ska.setByCSPRNG();
        const pka = mcl.mul(this.g, ska);
        return [ska, pka]
    }

    /**
     * Generate key pairs in G2
     * @returns  {[Object, Object]} - [secret key, public key]
     */
    keyGenInG2() {
        const skb = new mcl.Fr();
        skb.setByCSPRNG();
        const pkb = mcl.mul(this.h, skb);
        return [skb, pkb]
    }

    /**
     * PRE Encryption
     * @param {string} plain - plain message to be encrypted
     * @param {object} pk - public key of the delegator
     * @returns {[Object, Object]} - [g^(pk*k), mZ^k]
     */
    encrypt(plain, pk) {
        const m = new mcl.Fr()
        m.setStr(plain, 16)
        const k = new mcl.Fr();
        k.setByCSPRNG();

        const gak = mcl.mul(pk, k);
        const Z = mcl.pairing(this.g, this.h);

        const mzk = mcl.add(m, mcl.hashToFr(mcl.pow(Z, k).serialize()));
        return [gak, mzk]

    }

    /**
     * PRE Decryption
     * @param {[Object, Object]} encrypted - [g^(pk*k), mZ^k]
     * @param {object} sk - secret key of the delegator
     * @returns {string} - the plain message
     */
    decrypt(encrypted, sk) {
        let [gak, mzk] = encrypted;
        const eah = mcl.pairing(gak, this.h);
        const eahInvSk = mcl.pow(eah, mcl.inv(sk));
        return mcl.sub(mzk, mcl.hashToFr(eahInvSk.serialize())).getStr(16)
    }

    /**
     * PRE ReEncryption
     * @param {[Object, Object]} encrypted - [g^(pk*k), mZ^k]
     * @param {Object} reKey - the Transfer Key
     * @returns {[Object, Object]} encrypted - [Z^(pk*k), mZ^k]
     */
    static reEncrypt(encrypted, reKey) {
        let [gak, mzk] = encrypted;
        const Zbk = mcl.pairing(gak, reKey)
        return [Zbk, mzk]
    }

    /**
     * PRE ReDecryption
     * @param {[Object, Object]} reEncrypted - [Z^(pk*k), mZ^k]
     * @param {Object} sk - secret key of the delegatee
     * @returns {string} - the plain message
     */
    static reDecrypt(reEncrypted, sk) {

        let [Zbk, mzk] = reEncrypted;
        const ZbkInvB = mcl.pow(Zbk, mcl.inv(sk));

        return mcl.sub(mzk, mcl.hashToFr(ZbkInvB.serialize())).getStr(16)

    }

    static rekeyGen(ska, pkb) {
        return mcl.mul(pkb, mcl.inv(ska))
    }

}

class Delegator {
    /**
     *
     * @param  {PRE} pre
     */
    constructor(pre) {
        const keys = pre.keyGenInG1()
        this.sk = keys[0]
        this.pk = keys[1]
        this.pre = pre
    }

    encrypt(plain) {
        return this.pre.encrypt(plain, this.pk)
    }

    decrypt(encrypted) {
        return this.pre.decrypt(encrypted, this.sk)
    }


    reKeyGen(pkb) {
        return PRE.rekeyGen(this.sk, pkb)
    }

}

class Delegatee {
    /**
     *
     * @param  {PRE} pre
     */
    constructor(pre) {
        const keys = pre.keyGenInG2()
        this.sk = keys[0]
        this.pk = keys[1]
    }

    reDecrypt(reEncrypted) {
        return PRE.reDecrypt(reEncrypted, this.sk)
    }

}

class Proxy {
    static reEncrypt(encrypted, reKey) {
        return PRE.reEncrypt(encrypted, reKey)
    }
}

module.exports = {PRE, Delegator, Delegatee, Proxy};
