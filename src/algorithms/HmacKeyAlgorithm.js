/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')

/**
 * HmacKeyAlgorithm
 */
class HmacKeyAlgorithm extends KeyAlgorithm {

  /**
   * Constructor
   */
  constructor () {}

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
  sign (key, data) {}

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
  verify (key, signature, data) {}

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
  generateKey (params, extractable, usages) {}

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
