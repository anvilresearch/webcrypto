/**
 * Package dependencies
 */
const RSA = require('node-rsa')
const crypto = require('crypto')

/**
 * Local dependencies
 */
const {buf2ab,ab2buf} = require('../encodings')
const CryptoKey = require('../CryptoKey')
const CryptoKeyPair = require('../CryptoKeyPair')
const KeyAlgorithm = require('./KeyAlgorithm')
const RsaKeyAlgorithm = require('./RsaKeyAlgorithm')
const OperationError = require('../errors/OperationError')
const InvalidAccessError = require('../errors/InvalidAccessError')

/**
 * RsaHashedKeyAlgorithm
 */
class RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {

  /**
   * constructor
   *
   * @param {object} algorithm
   */
  constructor (algorithm) {
    super(algorithm)

    // validate hash
    if (!(this.hash instanceof KeyAlgorithm)) {
      throw new Error('hash of RsaHashedKeyAlgorithm must be a KeyAlgorithm')
    }
  }

  /**
   * sign
   *
   * @description
   * Create an RSA digital signature
   *
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @returns {string}
   */
  sign (key, data) {
    if (key.type !== 'private') {
      throw new InvalidAccessError()
    }

    try {
      let pem = key.key
      let signer = crypto.createSign('RSA-SHA256')

      signer.update(data.toString())
      return buf2ab(signer.sign(pem))
    } catch (error) {
      throw new OperationError()
    }
  }

  /**
   * verify
   *
   * @description
   *
   * @param {CryptoKey} key
   * @param {BufferSource} signature
   * @param {BufferSource} data
   *
   * @returns {Boolean}
   */
  verify (key, signature, data) {
    if (key.type !== 'public') {
      throw new InvalidAccessError()
    }

    try {
      let pem = key.key
      let verifier = crypto.createVerify('RSA-SHA256')

      verifier.update(data)
      return verifier.verify(pem, ab2buf(signature))
    } catch (error) {
      throw new OperationError()
    }
  }

  /**
   * generateKey
   *
   * @description
   * Generate an RSA key pair
   *
   * @param {RsaHashedKeyGenParams} params
   * @returns {CryptoKeyPair}
   */
  generateKey (params, extractable, usages) {

    // validate usages
    usages.forEach(usage => {
      if (usage !== 'sign' && usage !== 'verify') {
        throw new SyntaxError()
      }
    })

    let keypair

    // Generate RSA keypair
    try {
      // TODO
      // - fallback on system OpenSSL + child_process
      // - what is this bit option, where do we get the value from in this api?
      let key = new RSA({b:512})
      let {modulusLength,publicExponent} = params
      keypair = key.generateKeyPair(modulusLength, publicExponent)

    // cast error
    } catch (error) {
      throw new OperationError()
    }

    // cast params to algorithm
    let algorithm = new RsaHashedKeyAlgorithm(params)

    // instantiate publicKey
    let publicKey = new CryptoKey({
      type: 'public',
      algorithm,
      extractable: true,
      usages: ['verify'],
      key: keypair.exportKey('public')
    })

    // instantiate privateKey
    let privateKey = new CryptoKey({
      type: 'private',
      algorithm,
      // TODO is there a typo in the spec?
      // it says "extractable" instead of "false"
      extractable: false,
      usages: ['sign'],
      key: keypair.exportKey('private')
    })

    // return a new keypair
    return new CryptoKeyPair({publicKey,privateKey})
  }

  /**
   * importKey
   *
   * @description
   * @param {}
   * @returns {}
   */
  importKey () {
    // TODO
  }

  /**
   * exportKey
   *
   * @description
   * @param {}
   * @returns {}
   */
  exportKey () {
    // TODO
  }
}

/**
 * Export
 */
module.exports = RsaHashedKeyAlgorithm
