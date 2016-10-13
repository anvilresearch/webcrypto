/**
 * Module dependencies
 */
const crypto = require('crypto')
const KeyAlgorithm = require('./KeyAlgorithm')
const {TextEncoder, TextDecoder} = require('text-encoding')

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
   * @returns {Uint8Array}
   */
  digest (algorithm, data) {
    let result
    let {name} = algorithm
    let ab = data.buffer
    let dataBuffer = new Buffer(new Uint8Array(ab))

    if (name === 'SHA-1') {
      let hash = crypto.createHash('sha1')
      hash.update(dataBuffer)
      result = hash.digest()

    } else if (name === 'SHA-256') {
      let hash = crypto.createHash('sha256')
      hash.update(dataBuffer)
      result = hash.digest()

    } else if (name === 'SHA-384') {
      let hash = crypto.createHash('sha384')
      hash.update(dataBuffer)
      result = hash.digest()

    } else if (name === 'SHA-512') {
      let hash = crypto.createHash('sha512')
      hash.update(dataBuffer)
      result = hash.digest()

    } else {
      throw new OperationError()
    }

    return new Uint8Array(result.buffer)
  }
}

/**
 * Export
 */
module.exports = ShaKeyAlgorithm
