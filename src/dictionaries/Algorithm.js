'use strict'

/**
 * Module Dependencies
 * @ignore
 */
const Dictionary = require('./Dictionary')

/**
 * Algorithm
 */
class Algorithm extends Dictionary {

  /**
   * constructor
   *
   * @description
   * The Algorithm object is a dictionary object [WebIDL] which is used
   * to specify an algorithm and any additional parameters required to
   * fully specify the desired operation.
   *
   * @param {String|Object} algorithm
   */
  constructor (algorithm) {
    super(algorithm)

    if (!this.name) {
      throw new SyntaxError('Algorithm must have a name')
    }

    if (typeof this.name !== 'string') {
      throw new TypeError('Algorithm name must be a string')
    }
  }
}

/**
 * Export
 * @ignore
 */
module.exports = Algorithm
