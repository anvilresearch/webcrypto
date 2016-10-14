/**
 * Local dependencies
 */
const Algorithm = require('./Algorithm')

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
  }

  /**
   * validate
   */
  validate () {
    // validate modulusLength
    if (typeof this.modulusLength !== 'number') {
      throw new Error()
    }

    if (this.modulusLength < 1024) {
      throw new Error()
    }

    // validate publicExponent
    if (!(this.publicExponent instanceof Uint8Array)) {
      throw new Error()
    }
  }
}

/**
 * Export
 */
module.exports = RsaKeyGenParams
