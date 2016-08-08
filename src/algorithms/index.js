/**
 * Module dependencies
 */
const Algorithm = require('./Algorithm')
const KeyAlgorithm = require('./KeyAlgorithm')
const NotSupportedError = require('../errors/NotSupportedError')
const supportedAlgorithms = require('./supportedAlgorithms')

/**
 * Algorithms
 */
const algorithms = {
  'AES-CBC': require('./AES-CBC'),
  'AES-CFB': require('./AES-CFB'),
  'AES-CMAC': require('./AES-CMAC'),
  'AES-CTR': require('./AES-CTR'),
  'AES-GCM': require('./AES-GCM'),
  'AES-KW': require('./AES-KW'),
  'Concat-KDF': require('./Concat-KDF'),
  'Diffie-Hellman': require('./Diffie-Hellman'),
  'ECDH': require('./ECDH'),
  'ECDSA': require('./ECDSA'),
  'HKDF-CTR': require('./HKDF-CTR'),
  'HMAC': require('./HMAC'),
  'PBKDF2': require('./PBKDF2'),
  'RSA-OAEP': require('./RSA-OAEP'),
  'RSA-PSS': require('./RSA-PSS'),
  'SHA': require('./SHA')
}

/**
 * Normalize Algorithm
 *
 * @param {string} op
 * @param {string|AlgorithmIdentifier} alg
 */
function normalize (op, alg) {
  // string argument
  if (typeof alg === 'string') {
    return this.normalize(op, new KeyAlgorithm({ name: alg }))
  }

  // object argument
  if (typeof alg === 'object') {
    let initialAlg, algName, desiredType, normalizedAlgorithm

    let registeredAlgorithms = supportedAlgorithms[op]

    try {
      initialAlg = new Algorithm(alg)
    } catch (error) {
      return error
    }

    algName = registeredAlgorithms.getCaseInsensitive(initialAlg.name)

    if (algName) {
      desiredType = registeredAlgorithms[algName]
    } else {
      return new NotSupportedError(algName)
    }

    try {
      normalizedAlgorithm = new desiredType(initialAlg)
    } catch (error) {
      return error
    }

    return normalizedAlgorithm
  }
}

/**
 * Export
 */
module.exports = {normalize}
