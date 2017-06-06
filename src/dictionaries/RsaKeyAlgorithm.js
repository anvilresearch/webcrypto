/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')

/**
 * RsaKeyAlgorithm
 */
class RsaKeyAlgorithm extends KeyAlgorithm {

  /**
   * constructor
   *
   * @param {object} algorithm
   */
  constructor (algorithm) {
    // Call parent constructor then validate sundry tests
    super(algorithm)
    /* FIXME Implement to pass tests
    // validate type of modulusLength
    if (typeof this.modulusLength !== 'number') {
      throw new Error(
        'modulusLength of RsaKeyAlgorithm must be a number'
      )
    }

    // validate range of modulusLength
    if (this.modulusLength < 1024) {
      throw new Error(
        'modulusLength of RsaKeyAlgorithm must be at least 1024'
      )
    }

    // validate publicExponent
    if (!(this.publicExponent instanceof Uint8Array)) {
      throw new Error(
        'publicExponent of RsaKeyAlgorithm must be a BigInteger'
      )
    }*/
  }
}

/**
 * Export
 */
module.exports = RsaKeyAlgorithm
