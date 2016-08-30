/**
 * Module dependencies
 */
const crypto = require('crypto')
const KeyAlgorithm = require('./KeyAlgorithm')
const {ab2buf, buf2ab} = require('../encodings')

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
  digest (algorithm, data) {
    let result
    let {name} = algorithm

    if (name === 'SHA-1') {
      let hash = crypto.createHash('sha1')
      hash.update(ab2buf(data))
      result = hash.digest()

    } else if (name === 'SHA-256') {
      let hash = crypto.createHash('sha256')
      hash.update(ab2buf(data))
      result = hash.digest()

    } else if (name === 'SHA-384') {
      let hash = crypto.createHash('sha384')
      hash.update(ab2buf(data))
      result = hash.digest()

    } else if (name === 'SHA-512') {
      let hash = crypto.createHash('sha512')
      hash.update(ab2buf(data))
      result = hash.digest()

    } else {
      throw new OperationError()
    }

    return buf2ab(result)
  }
}

/**
 * Export
 */
module.exports = ShaKeyAlgorithm
