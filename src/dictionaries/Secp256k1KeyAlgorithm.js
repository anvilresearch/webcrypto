/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')

/**
 * AesKeyAlgorithm
 */
class Secp251kaKeyAlgorithm extends KeyAlgorithm {

  /**
   * Constructor
   */
  constructor (algorithm) {
    super(algorithm)
    //TODO Do more here.
  }
}

/**
 * Export
 */
module.exports = Secp251kaKeyAlgorithm
