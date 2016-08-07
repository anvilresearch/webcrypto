/**
 * Package dependencies
 */
const RSA = require('node-rsa')

/**
 * Local dependencies
 */
const CryptoKey = require('../CryptoKey')
const CryptoKeyPair = require('../CryptoKeyPair')
const KeyAlgorithm = require('./KeyAlgorithm')
const RsaKeyAlgorithm = require('./RsaKeyAlgorithm')
const NotSupportedError = require('./NotSupportedError')

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
   * encrypt
   *
   * @description
   * encrypt is not a supported operation for this algorithm.
   */
  encrypt () {
    throw new NotSupportedError()
  }

  /**
   * decrypt
   *
   * @description
   * decrypt is not a supported operation for this algorithm.
   */
  decrypt () {
    throw new NotSupportedError()
  }

  /**
   * sign
   *
   * @description
   *
   * @param {}
   *
   * @returns {}
   */
  sign () {
    // TODO
    throw new NotSupportedError()
  }

  /**
   * verify
   *
   * @description
   *
   * @param {}
   *
   * @returns {}
   */
  verify () {
    // TODO
    throw new NotSupportedError()
  }

  /**
   * deriveBits
   *
   * @description
   * deriveBits is not a supported operation for this algorithm.
   */
  deriveBits () {
    throw new NotSupportedError()
  }

  /**
   * wrapKey
   *
   * @description
   * wrapKey is not a supported operation for this algorithm.
   */
  wrapKey () {
    throw new NotSupportedError()
  }

  /**
   * unwrapKey
   *
   * @description
   * unwrapKey is not a supported operation for this algorithm.
   */
  unwrapKey () {
    throw new NotSupportedError()
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
    // TODO where does usages come from? arg? this?
    usages.forEach(usage => {
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
      let {modulusLength,publicExponent} = params
      let keypair = key.generateKeyPair(modulusLength, publicExponent)

      console.log(keypair.exportKey('public'), keypair.exportKey('private'))
      // TODO
      // - fallback on system OpenSSL + child_process
      // - how do we bind the results to the generated CryptoKey objects?
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
    // TODO
    throw new NotSupportedError()
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
    throw new NotSupportedError()
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
    throw new NotSupportedError()
  }

  /**
   * getLength
   *
   * @description
   * getLength is not a supported operation for this algorithm.
   */
  getLength () {
    throw new NotSupportedError()
  }
}

/**
 * Export
 */
module.exports = RsaHashedKeyAlgorithm
