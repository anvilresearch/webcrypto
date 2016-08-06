/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')
const RsaKeyGenParams = require('./RsaKeyGenParams')

/**
 * RsaHashedKeyGenParams
 */
class RsaHashedKeyGenParams extends RsaKeyGenParams {
  constructor (algorithm) {
    super(algorithm)

    // validate hash is an object
    if (typeof this.hash !== 'object') {
      throw new Error(
        'hash of RsaHashedKeyGenParams must be an object'
      )
    }

    // ensure hash is a KeyAlgorithm
    if (!(this.hash instanceof KeyAlgorithm)) {
      this.hash = new KeyAlgorithm(this.hash)
    }
  }
}

/**
 * Export
 */
module.exports = RsaHashedKeyGenParams
