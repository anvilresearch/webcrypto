/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')
const RsaKeyGenParams = require('./RsaKeyGenParams')

/**
 * RsaHashedKeyGenParams
 */
class RsaHashedKeyGenParams extends RsaKeyGenParams {

  /**
   * constructor
   */
  constructor (algorithm) {
    super(algorithm)
  }

  /**
   * validate
   */
  validate () {
    // validate hash is an object
    if (typeof this.hash !== 'object') {
      throw new Error(
        'hash of RsaHashedKeyGenParams must be an object'
      )
    }
  }
}

/**
 * Export
 */
module.exports = RsaHashedKeyGenParams
