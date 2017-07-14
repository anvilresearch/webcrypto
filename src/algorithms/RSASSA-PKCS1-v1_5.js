/**
 * Package dependencies
 */
const RSA = require('node-rsa')
const crypto = require('crypto')
const {spawnSync} = require('child_process')
const keyto = require('@trust/keyto')
const {TextEncoder, TextDecoder} = require('text-encoding')

/**
 * Local dependencies
 */
const Algorithm = require ('../algorithms/Algorithm')
const CryptoKey = require('../keys/CryptoKey')
const CryptoKeyPair = require('../keys/CryptoKeyPair')
const JsonWebKey = require('../keys/JsonWebKey')
const KeyAlgorithm = require('../dictionaries/KeyAlgorithm')
const RsaKeyAlgorithm = require('../dictionaries/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../dictionaries/RsaHashedKeyAlgorithm')
const supportedAlgorithms = require('../algorithms')

/**
 * Errors
 */
const {
  DataError,
  OperationError,
  InvalidAccessError,
  KeyFormatNotSupportedError
} = require('../errors')

/**
 * RSASSA_PKCS1_v1_5
 */
class RSASSA_PKCS1_v1_5 extends Algorithm {

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
   * @returns {ArrayBuffer}
   */
  sign (key, data) {
    if (key.type !== 'private') {
      throw new InvalidAccessError('Signing requires a private key')
    }

    try {
      let pem = key.handle
      data = new TextDecoder().decode(data)
      let signer = crypto.createSign('RSA-SHA256') // FIXME Paramaterize
      signer.update(data)
      return signer.sign(pem).buffer
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

      data = Buffer.from(data)
      signature = Buffer.from(signature)

      let verifier = crypto.createVerify('RSA-SHA256')
      verifier.update(data)

      return verifier.verify(pem, signature)
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
        throw new SyntaxError('Key usages can only include "sign" and "verify"')
      }
    })

    let keypair = {}

    // Generate RSA keypair
    try {
      let {modulusLength,publicExponent} = params
      // TODO
      // - fallback on node-rsa if OpenSSL is not available on the system
      let privateKey = spawnSync('openssl', ['genrsa', modulusLength || 4096]).stdout
      let publicKey = spawnSync('openssl', ['rsa', '-pubout'], { input: privateKey }).stdout
      try {
        keypair.privateKey = privateKey.toString('ascii')
        keypair.publicKey = publicKey.toString('ascii')
      } catch (error){
        throw new OperationError(error.message)
      }
      // - what is this bit option, where do we get the value from in this api?
      //let key = new RSA({b:512})
      //let {modulusLength,publicExponent} = params
      //keypair = key.generateKeyPair()//(modulusLength, publicExponent)

    // cast error
    } catch (error) {
      throw new OperationError(error.message)
    }

    // cast params to algorithm
    let algorithm = new RSASSA_PKCS1_v1_5(params)

    // instantiate publicKey
    let publicKey = new CryptoKey({
      type: 'public',
      algorithm,
      extractable: true,
      usages: ['verify'],
      handle: keypair.publicKey
    })

    // instantiate privateKey
    let privateKey = new CryptoKey({
      type: 'private',
      algorithm,
      extractable: extractable,
      usages: ['sign'],
      handle: keypair.privateKey
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
    let key, hash, normalizedHash, jwk

    if (format === 'spki') {
      // ...
    } else if (format === 'pkcs8') {

    } else if (format === 'jwk') {
      jwk = new JsonWebKey(keyData)

      if (jwk.d && keyUsages.some(usage => usage !== 'sign')) {
        throw new SyntaxError('Key usages must include "sign"')
      }

      if (jwk.d === undefined && !keyUsages.some(usage => usage === 'verify')) {
        throw new SyntaxError('Key usages must include "verify"')
      }

      if (jwk.kty !== 'RSA') {
        throw new DataError('Key type must be RSA')
      }

      if (jwk.use !== undefined && jwk.use !== 'sig') {
        throw new DataError('Key use must be "sig"')
      }

      // FIXME needs "ext" validation, see specification 6 under "jwk"

      // TODO
      //if (jwk.key_ops ...) {
      //  throw new DataError()
      //}

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
        // TODO
        // perform any key import steps defined by other applicable
        // specifications, passing format, jwk, and obtaining hash
        throw new DataError(
          'Key alg must be "RS1", "RS256", "RS384", or "RS512"'
        )
      }

      if (hash !== undefined) {
        normalizedHash = supportedAlgorithms.normalize('digest', hash)

        //if (normalizedHash !== normalizedAlgorithm.hash) {
        //  throw new DataError()
        //}

      }

      if (jwk.d) {
        // TODO
        // - validate JWK requirements
        key = new CryptoKey({
          type: 'private',
          extractable: extractable,
          usages: ['sign'],
          handle: keyto.from(jwk, 'jwk').toString('pem', 'private_pkcs1')
        })
      } else {
        // TODO
        // - validate JWK requirements
        key = new CryptoKey({
          type: 'public',
          extractable: true,
          usages: ['verify'],
          handle: keyto.from(jwk, 'jwk').toString('pem', 'public_pkcs8')
        })
      }
    } else {
      throw new KeyFormatNotSupportedError(format)
    }

    let alg = new RSASSA_PKCS1_v1_5({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: (new Buffer(jwk.n, 'base64').length / 2) * 8,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // TODO use jwk.e
      hash: normalizedHash
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
      throw new OperationError('Missing key material')
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

      Object.assign(jwk, keyto.from(key.handle, 'pem').toJwk(key.type))

      jwk.key_ops = key.usages
      jwk.ext = key.extractable

      // conversion to ECMAScript Object is implicit
      result = jwk
    } else {
      throw new KeyFormatNotSupportedError(format)
    }

    return result
  }
}

/**
 * Export
 */
module.exports = RSASSA_PKCS1_v1_5
