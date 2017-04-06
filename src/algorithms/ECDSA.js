/**
 * Local dependencies
 */
const Algorithm = require ('../algorithms/Algorithm')
const KeyAlgorithm = require('../dictionaries/KeyAlgorithm') 

/**
 * ECDSA Algorithm
 */
class ECDSA extends Algorithm {

  /**
   * sign
   *
   * @description
   * Create an ECDSA digital signature
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
    let hashAlgorithm = normalizedAlgorithm.hash
    // let M = 
  }

}

/**
 * Export
 */
module.exports = EcKeyAlgorithm
