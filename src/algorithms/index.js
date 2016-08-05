/**
 * Module dependencies
 */
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
  'RSASSA-PKCS1-v1_5': require('./RSASSA-PKCS1-v1_5'),
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
    return this.normalize(op, new KeyAlgorithm(alg, op))
  }

  // object argument
  let registeredAlgorithms = supportedAlgorithms[op]
  let initialAlg, algName, desiredType, normalizedAlgorithm

  try {
    initialAlg = new Algorithm(alg, op)
  } catch (error) {
    return error
  }

  let algName = initialAlg.name

  // TODO this should be a case-insensitive match
  if (registeredAlgorithms.includes(algName)) {
    algName = registeredAlgorithms.getCaseInsensitive(algName)
    desiredType = algorithms[algName]
  } else {
    return new NotSupportedError()
  }

  try {
    normalizedAlgorithm = new desiredType(initialAlg)
  } catch (error) {
    return error
  }

  return normalizedAlgorithm
}

/**
 * Export
 */
module.exports = normalize
