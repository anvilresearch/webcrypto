/**
 * Local dependencies
 */
const Algorithm = require('./Algorithm')
const BigInteger = require('../BigInteger')

/**
 * RsaKeyGenParams
 */
class RsaKeyGenParams extends Algorithm {

  /**
   * Constructor
   *
   * @param {number} modulusLength
   * @param {BigInteger} publicExponent
   */
  constructor (algorithm) {
    super(algorithm)

    // validate modulusLength
    if (typeof this.modulusLength !== 'number') {
      throw new Error()
    }

    if (this.modulusLength < 1024) {
      throw new Error()
    }

    // validate publicExponent
    if (!(this.publicExponent instanceof BigInteger)) {
      throw new Error()
    }
  }
}

/**
 * Export
 */
module.exports = RsaKeyGenParams
