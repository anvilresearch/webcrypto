/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')

/**
 * Mapping
 */
const mapping = [
  { namedCurve: 'P-256', name: 'prime256v1', alg: 'ES256', hash: 'sha256' },
  { namedCurve: 'P-384', name: 'secp384r1', alg: 'ES384', hash: 'sha384' },
  { namedCurve: 'P-521', name: 'secp521r1', alg: 'ES512', hash: 'sha512' },
  { namedCurve: 'K-256', name: 'secp256k1', alg: 'KS256', hash: 'sha256' },
]

/**
 * EcKeyAlgorithm
 */
class EcKeyAlgorithm extends KeyAlgorithm {

  /**
   * Constructor
   */
  constructor (algorithm) {
    super(algorithm)
  }

  static get mapping () {
    return mapping
  }
}

/**
 * Export
 */
module.exports = EcKeyAlgorithm
