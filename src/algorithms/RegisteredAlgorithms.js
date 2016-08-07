/**
 * RegisteredAlgorithms
 */
class RegisteredAlgorithms {

  /**
   * Constructor
   *
   * @param {Object} mapping
   */
  constructor (mapping) {
    Object.assign(this, mapping)
  }

  /**
   * getCaseInsensitive
   *
   * @param {string} algName
   * @returns {string}
   */
  getCaseInsensitive (algName) {
    for (let key in this) {
      if (key.match(new RegExp(`^${algName}$`, 'i'))) {
        return key
      }
    }
  }
}

/**
 * Export
 */
module.exports = RegisteredAlgorithms
