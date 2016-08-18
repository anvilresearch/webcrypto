/**
 * Module dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')

/**
 * ShaKeyAlgorithm
 */
class ShaKeyAlgorithm extends KeyAlgorithm {

  /**
   * dictionaries
   */
  static get dictionaries () {
    return [
      KeyAlgorithm,
      ShaKeyAlgorithm
    ]
  }

  /**
   * members
   */
  static get members () {
    return {}
  }


}

/**
 * Export
 */
module.exports = ShaKeyAlgorithm
