/**
 * Local dependencies
 */
const {NotSupportedError} = require('../errors')

/**
 * KeyAlgorithm dictionary
 */
class KeyAlgorithm {

  /**
   * constructor
   *
   * @param {object} algorithm
   */
  constructor (algorithm) {
    Object.assign(this, algorithm)

    // validate name
    if (this.name === undefined) {
      throw new Error('KeyAlgorithm must have a name')
    }
  }
}



/**
 * Export
 */
module.exports = KeyAlgorithm
