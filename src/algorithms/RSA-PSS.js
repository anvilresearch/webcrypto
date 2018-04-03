/**
 * Package dependencies
 */

const crypto = require('crypto')
const base64url = require('base64url').default
const keyto = require('@trust/keyto')
const {spawnSync} = require('child_process')
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
  KeyFormatNotSupportedError,
  CurrentlyNotSupportedError
} = require('../errors')

/**
 * RSA_PSS
 */
class RSA_PSS extends Algorithm {

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
      hash: 'HashAlgorithmIdentifier',
    }
  }

  /**
   * sign
   *
   * @description
   * Create an RSA-PSS digital signature
   *
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @returns {ArrayBuffer}
   */
  sign (key, data) {
    // 1. Ensure key type is 'private' only
    if (key.type !== 'private') {
      throw new InvalidAccessError('Signing requires a private key')
    }

    // Ensure saltLength exists
    if (this.saltLength === undefined){
      throw new OperationError('saltLength must be a valid integer')
    }


    // Parametrize hash
    let hashName 
    if (this.hash.name === 'SHA-1'){
      hashName = 'sha1'
    } else if (this.hash.name === 'SHA-256'){
      hashName = 'sha256'
    } else if (this.hash.name === 'SHA-384'){
      hashName = 'sha384'
    } else if (this.hash.name === 'SHA-512'){
      hashName = 'sha512'
    } else {
      throw new OperationError('Algorithm hash is an unknown format.')
    }

    // 2-5. Perform key signing and return result
    try {
      let pem = key.handle
      data = new TextDecoder().decode(data)
      let signer = crypto.createSign(hashName)
      signer.update(data)
      return signer.sign({
        key: pem,
        saltLength: this.saltLength,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING
      }).buffer
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
    // 1. Ensure key type is 'public' only
    if (key.type !== 'public') {
      throw new InvalidAccessError('Verifying requires a public key')
    }

    // Ensure saltLength exists
    if (this.saltLength === undefined){
      throw new OperationError('saltLength must be a valid integer')
    }

    // Parametrize hash
    let hashName 
    if (this.hash.name === 'SHA-1'){
      hashName = 'sha1'
    } else if (this.hash.name === 'SHA-256'){
      hashName = 'sha256'
    } else if (this.hash.name === 'SHA-384'){
      hashName = 'sha384'
    } else if (this.hash.name === 'SHA-512'){
      hashName = 'sha512'
    } else {
      throw new OperationError('Algorithm hash is an unknown format.')
    }

    // 2-4. Perform verification and return result
    try {
      let pem = key.handle

      data = Buffer.from(data)
      signature = Buffer.from(signature)

      let verifier = crypto.createVerify(hashName)
      verifier.update(data)

      return verifier.verify({
          key: pem,
          saltLength: this.saltLength,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        }, signature)
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

    // 1. Verify usages
    usages.forEach(usage => {
      if (usage !== 'sign' && usage !== 'verify') {
        throw new SyntaxError('Key usages can only include "sign" and "verify"')
      }
    })

    let keypair = {}

    // 2. Generate RSA keypair
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
    // 3. Throw operation error if anything fails
    } catch (error) {
      throw new OperationError(error.message)
    }

    // 4-9. Create and assign algorithm object
    let algorithm = new RSA_PSS(params)

    // 10-13. Instantiate publicKey
    let publicKey = new CryptoKey({
      type: 'public',
      algorithm,
      extractable: true,
      usages: ['verify'],
      handle: keypair.publicKey
    })

    // 14-18. Instantiate privateKey
    let privateKey = new CryptoKey({
      type: 'private',
      algorithm,
      extractable: extractable,
      usages: ['sign'],
      handle: keypair.privateKey
    })

    // 19-22. Create and return a new keypair
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
    // 1. Performed in function parameters
    // 2.1. "spki" format
    if (format === 'spki') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    } 
    // 2.2. "pkcs8" format
    else if (format === 'pkcs8') {
      throw new CurrentlyNotSupportedError(format,'jwk')
    } 
    // 2.3. "jwk" format
    else if (format === 'jwk') {
      // 2.3.1. Cast keyData to JWK object
      jwk = new JsonWebKey(keyData)

      // 2.3.2. Verify 'd' field
      if (jwk.d && keyUsages.some(usage => usage !== 'sign')) {
        throw new SyntaxError('Key usages must include "sign"')
      }
      if (jwk.d === undefined && !keyUsages.some(usage => usage === 'verify')) {
        throw new SyntaxError('Key usages must include "verify"')
      }

      // 2.3.3. Verify 'kty' field
      if (jwk.kty !== 'RSA') {
        throw new DataError('Key type must be RSA')
      }

      // 2.3.4. Verify 'use' field
      if (jwk.use !== undefined && jwk.use !== 'sig') {
        throw new DataError('Key use must be "sig"')
      }

      // 2.3.5. Validate present 'use' field and allowed string match
      if (jwk.use !== undefined && jwk.use !== 'sig') {
        throw new DataError('Key use must be "sig"')
      }

      // 2.3.6. Validate present 'key_ops' field 
      if (jwk.key_ops !== undefined) {
        jwk.key_ops.forEach(op => {
            if (op !== 'sign'
            && op !== 'verify') {
            throw new DataError('Key operation can only include "sign", and "verify".')
          }
        })
      }

      // 2.3.7-8. Determine hash name
      if (jwk.alg === undefined) {
        // keep undefined
      } else if (jwk.alg === 'PS1') {
        hash = 'SHA-1'
      } else if (jwk.alg === 'PS256') {
        hash = 'SHA-256'
      } else if (jwk.alg === 'PS384') {
        hash = 'SHA-384'
      } else if (jwk.alg === 'PS512') {
        hash = 'SHA-512'
      } else {
        throw new DataError(
          'Key alg must be "PS1", "PS256", "PS384", or "PS512"'
        )
      }

      // 2.3.9. Ommited due to redundancy
      if (hash !== undefined) {
        normalizedHash = supportedAlgorithms.normalize('digest', hash)
      }
      
      // 2.3.10. Verify 'd' field
      if (jwk.d) {
        key = new CryptoKey({
          type: 'private',
          extractable: extractable,
          usages: ['sign'],
          handle: keyto.from(jwk, 'jwk').toString('pem', 'private_pkcs1')
        })
      } else {
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
    // 3-7. Setup RSA PSS object
    let alg = new RSA_PSS({
      name: 'RSA-PSS',
      modulusLength: base64url.toBuffer(jwk.n).length * 8,
      publicExponent: new Uint8Array(base64url.toBuffer(jwk.e)),
      hash: normalizedHash
    })

    // 8. Set algorithm of key to alg
    key.algorithm = alg

    // 9. Return key
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
        jwk.alg = 'PS1'
      } else if (hash === 'SHA-256') {
        jwk.alg = 'PS256'
      } else if (hash === 'SHA-384') {
        jwk.alg = 'PS384'
      } else if (hash === 'SHA-512') {
        jwk.alg = 'PS512'
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
module.exports = RSA_PSS