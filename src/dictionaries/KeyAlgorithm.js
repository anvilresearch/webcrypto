'use strict'

/**
 * Module Dependencies
 * @ignore
 */
const Dictionary = require('./Dictionary')

/**
 * KeyAlgorithm
 */
class KeyAlgorithm extends Dictionary {

  /**
   * constructor
   *
   * @description
   * The KeyAlgorithm dictionary represents information about the contents of a given CryptoKey
   * object.
   *
   * @param {String|Object} algorithm
   */
  constructor (algorithm) {
    super(algorithm)

    if (!this.name) {
      throw new SyntaxError('KeyAlgorithm must have a name')
    }

    if (typeof this.name !== 'string') {
      throw new TypeError('KeyAlgorithm name must be a string')
    }
  }
}

/**
 * Export
 * @ignore
 */
module.exports = KeyAlgorithm
