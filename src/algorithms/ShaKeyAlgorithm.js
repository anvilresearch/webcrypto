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

  /**
   * digest
   *
   * @description
   *
   * @param {AlgorithmIdentifier} algorithm
   * @param {BufferSource} data
   *
   * @returns {ArrayBuffer}
   */
  digest (hash, data) {}

}

/**
 * Export
 */
module.exports = ShaKeyAlgorithm
