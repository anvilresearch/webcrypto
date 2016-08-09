/**
 * Module dependencies
 */
const Algorithm = require('./Algorithm')
const KeyAlgorithm = require('./KeyAlgorithm')
const NotSupportedError = require('../errors/NotSupportedError')
const supportedAlgorithms = require('./supportedAlgorithms')

/**
 * Normalize Algorithm
 *
 * @param {string} op
 * @param {string|AlgorithmIdentifier} alg
 */
function algorithm (op, alg) {
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
module.exports = {algorithm}
