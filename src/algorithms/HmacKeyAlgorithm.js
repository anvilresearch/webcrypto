/**
 * Native dependencies
 */
const crypto = require('crypto')

/**
 * Local dependencies
 */
const CryptoKey = require('../CryptoKey')
const KeyAlgorithm = require('./KeyAlgorithm')
const OperationError = require('../errors/OperationError')
const {ab2buf, buf2ab} = require('../encodings')

/**
 * HmacKeyAlgorithm
 */
class HmacKeyAlgorithm extends KeyAlgorithm {

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
    hmac.update(ab2buf(data))
    return buf2ab(hmac.digest())
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
    let mac = ab2buf(this.sign(key, data))
    signature = ab2buf(signature)
    return mac.equals(signature)
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

    if (this.length === undefined) {
      length = params.hash.name.match(/[0-9]+/)[0]
    } else if (this.length > 0) {
      length = this.length
    } else {
      new OperationError('Invalid HMAC length')
    }

    let generatedKey

    try {
      generatedKey = crypto.randomBytes(parseInt(length))
    } catch (e) {
      throw new OperationError('Failed to generate HMAC key')
    }

    let key = new CryptoKey({
      type: 'secret',
      algorithm: new HmacKeyAlgorithm({
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
  importKey (format, keyData, algorithm, extractable, keyUsages) {}

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
  exportKey (format, key) {}
}

/**
 * Export
 */
module.exports = HmacKeyAlgorithm
