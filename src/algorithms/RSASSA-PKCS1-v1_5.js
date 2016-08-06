/**
 * Package dependencies
 */
const crypto = require('crypto')
const RSA = require('node-rsa')

/**
 * Local dependencies
 */
const Algorithm = require('./Algorithm')
const BigInteger = require('../BigInteger')
const CryptoKey = require('../CryptoKey')
const CryptoKeyPair = require('../CryptoKeyPair')
const KeyAlgorithm = require('./KeyAlgorithm')
const RsaKeyGenParams = require('./RsaKeyGenParams')
const RsaHashedKeyGenParams = require('./RsaHashedKeyGenParams')
const RsaKeyAlgorithm = require('./RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('./RsaHashedKeyAlgorithm')
const RsaHashedImportParams = require('./RsaHashedImportParams')

/**
 * RSASSA-PKCS1-v1_5
 */
class RSASSA_PKCS1_v1_5 {

  /**
   * Constructor
   *
   * @param {RsaKeyAlgorithm} algorithm
   * @param {Boolean} extractable
   * @param {Array} usages
   */
  constructor (algorithm, extractable, usages) {
    this.algorithm = algorithm
    this.extractable = extractable
    this.usages = usages
  }

  /**
   * exportKey
   */
  exportKey () {}

  /**
   * generateKey
   *
   * @param {RsaHashedKeyGenParams} params
   * @returns {CryptoKeyPair}
   */
  generateKey (params) {
    // validate usages
    this.usages.forEach(usage => {
      if (usage !== 'sign' && usage !== 'verify') {
        throw new SyntaxError()
      }
    })

    // Generate and RSA keypair
    try {
      // TODO
      // what is this bit option, where do we get the value from in this
      // api?
      let key = new RSA({b:512})
      let {modulusLength,publicExponent} = this.algorithm
      let keypair = key.generateKeyPair(modulusLength, publicExponent)
      console.log('KEYPAIR', keypair)
    } catch (e) {
      throw new OperationError()
    }

    // cast params to algorithm
    let algorithm = new RsaHashedKeyAlgorithm(params)

    // instantiate publicKey
    let publicKey = new CryptoKey({
      type: 'public',
      algorithm,
      extractable: true,
      usages: ['verify']
    })

    // instantiate privateKey
    let privateKey = new CryptoKey({
      type: 'private',
      algorithm,
      // TODO is there a typo in the spec?
      // it says "extractable" instead of "false"
      extractable: false,
      usages: ['sign']
    })

    // return a new keypair
    return new CryptoKeyPair({publicKey,privateKey})
  }

  /**
   * importKey
   */
  importKey () {}

  /**
   * signKey
   */
  sign (key, data) {

  }

  /**
   * verifyKey
   */
  verify () {}
}

/**
 * Export
 */
module.exports = RSASSA_PKCS1_v1_5
