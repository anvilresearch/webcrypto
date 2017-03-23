/**
 * Algorithm
 */
class Algorithm {

  /**
   * constructor
   *
   * @description
   * The Algorithm object is a dictionary object [WebIDL] which is used
   * to specify an algorithm and any additional parameters required to
   * fully specify the desired operation.
   *
   * @param {string|Object} algorithm
   */
  constructor (algorithm) {
    if (typeof algorithm === 'string') {
      this.name = algorithm
    } else {
      Object.assign(this, algorithm)
      if (typeof this.name !== 'string') {
        throw new Error('Algorithm name must be a string')
      }
    }
  }
}

/**
 * Export
 */
module.exports = Algorithm
