/**
 * RegisteredAlgorithms
 */
class RegisteredAlgorithms extends Array {

  /**
   * Constructor
   *
   * @param {Array} collection
   */
  constructor (collection) {
    super()

    collection.forEach(item => {
      this.push(item)
    })
  }

  /**
   * getCaseInsensitive
   *
   * @param {string} algName
   * @returns {string}
   */
  getCaseInsensitive (algName) {
    return this.find(item => {
      return item.match(new RegExp(algName, 'i'))
    })
  }
}

/**
 * Export
 */
module.exports = RegisteredAlgorithms
