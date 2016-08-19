/**
 * Package dependencies
 */
const RSA = require('node-rsa')
const crypto = require('crypto')
const {pem2jwk} = require('pem-jwk')

/**
 * Local dependencies
 */
const {buf2ab,ab2buf} = require('../encodings')
const CryptoKey = require('../CryptoKey')
const CryptoKeyPair = require('../CryptoKeyPair')
const JsonWebKey = require('../JsonWebKey')
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
  }

  /**
   * dictionaries
   */
  static get dictionaries () {
    return [
      KeyAlgorithm,
      RsaKeyAlgorithm,
      RsaHashedKeyAlgorithm
    ]
  }

  /**
   * members
   */
  static get members () {
    return {
      name: String,
      modulusLength: Number,
      publicExponent: 'BufferSource',
      hash: 'HashAlgorithmIdentifier'
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
      throw new InvalidAccessError('Signing requires a private key')
    }

    try {
      let pem = key.handle
      let signer = crypto.createSign('RSA-SHA256')

      signer.update(ab2buf(data))
      return buf2ab(signer.sign(pem))
    } catch (error) {
      throw new OperationError(error.message)
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
      throw new InvalidAccessError('Verifying requires a public key')
    }

    try {
      let pem = key.handle
      let verifier = crypto.createVerify('RSA-SHA256')

      verifier.update(ab2buf(data))
      return verifier.verify(pem, ab2buf(signature))
    } catch (error) {
      throw new OperationError(error.message)
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
      keypair = key.generateKeyPair()//(modulusLength, publicExponent)

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
      handle: keypair.exportKey('public')
    })

    // instantiate privateKey
    let privateKey = new CryptoKey({
      type: 'private',
      algorithm,
      extractable: extractable,
      usages: ['sign'],
      handle: keypair.exportKey('private')
    })

    // return a new keypair
    return new CryptoKeyPair({publicKey,privateKey})
  }

  /**
   * importKey
   *
   * @description
   *
   * @param {string} format
   * @param {string|JsonWebKey} keyData
   * @param {KeyAlgorithm} algorithm
   * @param {Boolean} extractable
   * @param {Array} keyUsages
   *
   * @returns {CryptoKey}
   */
  importKey (format, keyData, algorithm, extractable, keyUsages) {
    let key

    if (format === 'spki') {
      // ...
    } else if (format === 'pkcs8') {

    } else if (format === 'jwk') {
      let jwk = new JsonWebKey(keyData)

      if (jwk.d && usages.some(usage => usage !== 'sign')) {
        throw new SyntaxError()
      }

      if (jwk.d === undefined && usages.some(usage => usage !== 'verify')) {
        throw new SyntaxError()
      }

      if (jwk.kty !== 'RSA') {
        throw new DataError()
      }

      if (jwk.use !== undefined && jwk.use !== 'sig') {
        throw new DataError()
      }

      // TODO
      //if (jwk.key_ops ...) {
      //  throw new DataError()
      //}

      let hash

      if (jwk.alg === undefined) {
        // leave hash undefined
      } else if (jwk.alg === 'RS1') {
        hash = 'SHA-1'
      } else if (jwk.alg === 'RS256') {
        hash = 'SHA-256'
      } else if (jwk.alg === 'RS384') {
        hash = 'SHA-384'
      } else if (jwk.alg === 'RS512') {
        hash = 'SHA-512'
      } else {
        // perform any key import steps defined by other applicable specifications
        // passing format, jwk, and obtaining hash

        throw new DataError()
      }

      if (hash !== undefined) {
        let normalizedHash = algorithms.normalize('digest', hash)

        if (normalizedHash !== normalizedAlgorithm.hash) {
          throw new DataError()
        }

        if (jwk.d) {
          // TODO
          // - validate JWK requirements
          // - translate JWK to PEM
          key = new CryptoKey({
            type: 'private',
            //algorithm,
            //extractable: false,
            usages: ['sign'],
            handle: jwk2pem(jwk)
          })
        } else {
          // TODO
          // - validate JWK requirements
          // - translate JWK to PEM
          key = new CryptoKey({
            type: 'public',
            //algorithm,
            //extractable: false,
            usages: ['verify'],
            handle: jwk2pem(jwk)
          })
        }
      }
    } else {
      throw new NotSupportedError()
    }

    let alg = new RsaHashedKeyAlgorithm({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: getBitLength(jwk.n),
      publicExponent: new BigInteger(jwk.e),
      hash: hash
    })

    key.algorithm = alg

    return key
  }

  /**
   * exportKey
   *
   * @description
   *
   * @param {string} format
   * @param {CryptoKey} key
   *
   * @returns {*}
   */
  exportKey (format, key) {
    let result

    // TODO
    // - should we type check key here?
    if (!key.handle) {
      throw new OperationError()
    }

    if (format === 'spki') {
      // TODO
    } else if (format === 'pkcs8') {
      // TODO
    } else if (format === 'jwk') {
      let jwk = new JsonWebKey({ kty: 'RSA' })
      let hash = key.algorithm.hash.name

      if (hash === 'SHA-1') {
        jwk.alg = 'RS1'
      } else if (hash === 'SHA-256') {
        jwk.alg = 'RS256'
      } else if (hash === 'SHA-384') {
        jwk.alg = 'RS384'
      } else if (hash === 'SHA-512') {
        jwk.alg = 'RS512'
      } else {
        // TODO other applicable specifications
      }

      Object.assign(jwk, pem2jwk(key.handle))

      jwk.key_ops = key.usages
      jwk.ext = key.extractable

      // conversion to ECMAScript Object is implicit
      result = jwk
    } else {
      throw new NotSupportedError()
    }

    return result
  }
}

/**
 * Export
 */
module.exports = RsaHashedKeyAlgorithm
