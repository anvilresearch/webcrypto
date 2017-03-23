/**
 * Package dependencies
 */
const base64url = require('base64url')
const crypto = require('crypto')

/**
 * Local dependencies
 */
const Algorithm = require ('../algorithms/Algorithm')
const CryptoKey = require('../keys/CryptoKey')
const JsonWebKey = require('../keys/JsonWebKey')
const KeyAlgorithm = require('../dictionaries/KeyAlgorithm')
const HmacKeyAlgorithm = require('../dictionaries/HmacKeyAlgorithm')

/**
 * Errors
 */
const {
  DataError,
  OperationError,
  NotSupportedError,
  KeyFormatNotSupportedError
} = require('../errors')

/**
 * HMAC
 */
class HMAC extends Algorithm {

  /**
   * dictionaries
   */
  static get dictionaries () {
    return [
      KeyAlgorithm,
      HmacKeyAlgorithm
    ]
  }

  /**
   * members
   */
  static get members () {
    return {}
  }

  /**
   * sign
   *
   * @description
   * Create a MAC
   *
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @return {string}
   */
  sign (key, data) {
    let alg = key.algorithm.hash.name.replace('-', '').toLowerCase()
    let hmac = crypto.createHmac(alg, key.handle)
    hmac.update(Buffer.from(data))
    return new Uint8Array(hmac.digest()).buffer
  }

  /**
   * verify
   *
   * @description
   * Verify a MAC
   *
   * @param {CryptoKey} key
   * @param {BufferSource} signature
   * @param {BufferSource} data
   *
   * @returns {Boolean}
   */
  verify (key, signature, data) {
    let mac = Buffer.from(this.sign(key, data))
    return mac.equals(Buffer.from(signature))
  }

  /**
   * generateKey
   *
   * @description
   * Generate HMAC key
   *
   * @param {HmacKeyGenParams} params
   * @param {Boolean} extractable
   * @param {Array} usages
   *
   * @returns {CryptoKey}
   */
  generateKey (params, extractable, usages) {
    usages.forEach(usage => {
      if (usage !== 'sign' && usage !== 'verify') {
        throw new SyntaxError(
          'Key usages can only include "sign" and "verify"'
        )
      }
    })

    let length

    if (params.length === undefined) {
      length = params.hash.name.match(/[0-9]+/)[0]
    } else if (params.length > 0) {
      length = params.length
    } else {
      throw new OperationError('Invalid HMAC length')
    }

    let generatedKey

    try {
      generatedKey = crypto.randomBytes(parseInt(length))
    } catch (e) {
      throw new OperationError('Failed to generate HMAC key')
    }

    let key = new CryptoKey({
      type: 'secret',
      algorithm: new HMAC({
        name: 'HMAC',
        hash: new KeyAlgorithm({
          name: params.hash.name
        })
      }),
      extractable,
      usages,
      handle: generatedKey
    })

    return key
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
    keyUsages.forEach(usage => {
      if (usage !== 'sign' && usage !== 'verify') {
        throw new SyntaxError(
          'Key usages can only include "sign" and "verify"'
        )
      }
    })

    let hash = new KeyAlgorithm({ name: 'HMAC' })
    let data

    if (format === 'raw') {
      data = new Buffer(keyData)

      if (algorithm.hash) {
        hash = algorithm.hash
      } else {
        throw new TypeError('HmacKeyGenParams: hash: Missing or not an AlgorithmIdentifier')
      }

    } else if (format === 'jwk') {
      let jwk = new JsonWebKey(keyData)

      if (jwk.kty !== 'oct') {
        throw new DataError()
      }

      data = base64url.toBuffer(jwk.k)

      if (algorithm.hash !== undefined) {
        hash = algorithm.hash

        if (hash.name === 'SHA-1') {
          if (jwk.alg && jwk.alg !== 'HS1') {
            throw new DataError()
          }
        } else if (hash.name === 'SHA-256') {
          if (jwk.alg && jwk.alg !== 'HS256') {
            throw new DataError()
          }
        } else if (hash.name === 'SHA-384') {
          if (jwk.alg && jwk.alg !== 'HS384') {
            throw new DataError()
          }
        } else if (hash.name === 'SHA-512') {
          if (jwk.alg && jwk.alg !== 'HS512') {
            throw new DataError()
          }
        // TODO
        // "another applicable specification"
        //} else if () {
        //  ...
        } else {
          throw new DataError()
        }
      } else {
        if (jwk.alg === undefined) {
          throw new DataError()
        }

        if (jwk.alg === 'HS1') {
          hash.name = 'SHA-1'
        } else if (jwk.alg === 'HS256') {
          hash.name = 'SHA-256'
        } else if (jwk.alg === 'HS384') {
          hash.name = 'SHA-384'
        } else if (jwk.alg === 'HS512') {
          hash.name = 'SHA-512'
        } else {
          // TODO
          // "other applicable specifications"
        }
      }

      if (jwk.use !== undefined && jwk.use !== 'sign') {
        throw new DataError()
      }

      if (jwk.key_ops !== undefined) {
        //if (jwk.key_ops ...?) {
        //  throw new DataError()
        //}

        keyUsages.forEach(usage => {
          if (!jwk.key_ops.includes(usage)) {
            throw new DataError()
          }
        })
      }

      if (jwk.ext === false && extractable === true) {
        throw new DataError()
      }

    } else {
      throw new KeyFormatNotSupportedError(format)
    }

    let length = data.length * 8

    if (length === 0) {
      throw new DataError('HMAC key data must not be empty')
    }

    if (algorithm.length !== undefined) {
      if (algorithm.length > length) {
        throw new DataError()
      } else if (algorithm.length <= length - 8) {
        throw new DataError()
      } else {
        length = algorithm.length
      }
    }

    let key = new CryptoKey({
      type: 'secret',
      algorithm: new HMAC({
        name: 'HMAC',
        length,
        hash
      }),
      extractable,
      usages: keyUsages,
      handle: data
    })

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
    if (!(key instanceof CryptoKey) || key.handle === undefined) {
      throw new OperationError('argument must be CryptoKey')
    }

    let result

    if (format === 'raw') {
      let data = key.handle
      result = Buffer.from(data)

    } else if (format === 'jwk') {
      let jwk = new JsonWebKey({
        kty: 'oct',
        k: base64url(key.handle)
      })

      let algorithm = key.algorithm
      let hash = algorithm.hash

      if (hash.name === 'SHA-1') {
        jwk.alg = 'HS1'
      } else if (hash.name === 'SHA-256') {
        jwk.alg = 'HS256'
      } else if (hash.name === 'SHA-384') {
        jwk.alg = 'HS384'
      } else if (hash.name === 'SHA-512') {
        jwk.alg = 'HS512'
      } else {
        // TODO
        // "other applicable specifications"
      }

      jwk.key_ops = key.usages
      jwk.ext = key.extractable

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
module.exports = HMAC
