/**
 * Local dependencies
 */
const KeyAlgorithm = require('./KeyAlgorithm')

/**
 * Mapping
 */
const mapping = [
  { namedCurve: 'P-256', name: 'secp256r1', alg: 'ES256' },
  { namedCurve: 'P-384', name: 'secp384r1', alg: 'ES384' },
  { namedCurve: 'P-512', name: 'secp521r1', alg: 'ES512' },
  { namedCurve: 'K-256', name: 'secp256k1', alg: 'KS256' },
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
