'use strict'

/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')
const DataError = require('../errors/DataError')

/**
 * RsaKeyAlgorithm
 */
class RsaKeyAlgorithm extends KeyAlgorithm {

  /**
   * Constructor
   *
   * @param {Object} algorithm
   * @param {String} algorithm.name
   * @param {Number} algorithm.modulusLength
   * @param {BigInteger} algorithm.publicExponent
   */
  constructor (algorithm) {
    super(algorithm)

    // required
    if (!this.modulusLength) {
      throw new SyntaxError('modulusLength is required')
    }

    if (typeof this.modulusLength !== 'number') {
      throw new TypeError('modulusLength must be a number')
    }

    // unsigned long
    this.modulusLength = RsaKeyAlgorithm.coerceNumber(this.modulusLength, 'unsigned long')

    // Minimum modulusLength
    if (this.modulusLength < 1024) {
      throw new DataError('modulusLength must be at least 1024')
    }

    // required
    if (!this.publicExponent) {
      throw new SyntaxError('publicExponent is required')
    }

    // validate publicExponent
    if (!(this.publicExponent instanceof Uint8Array)) {
      throw new TypeError('publicExponent must be a BigInteger')
    }
  }
}

/**
 * Export
 */
module.exports = RsaKeyAlgorithm
