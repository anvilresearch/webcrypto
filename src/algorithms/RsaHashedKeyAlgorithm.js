/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')
const RsaKeyAlgorithm = require('./RsaKeyAlgorithm')

/**
 * RsaHashedKeyAlgorithm
 */
class RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {

  /**
   * constructor
   *
   * @param {object} algorithm
   */
  constructor (algorithm) {
    super(algorithm)

    // validate hash
    if (!(this.hash instanceof KeyAlgorithm)) {
      throw new Error('hash of RsaHashedKeyAlgorithm must be a KeyAlgorithm')
    }
  }
}

/**
 * Export
 */
module.exports = RsaHashedKeyAlgorithm
