'use strict'

/**
 * Local dependencies
 */
const RsaKeyAlgorithm = require('./RsaKeyAlgorithm')
const Algorithm = require('./Algorithm')

/**
 * RsaHashedKeyAlgorithm
 */
class RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {

  /**
   * constructor
   */
  constructor (algorithm) {
    super(algorithm)

    if (!this.hash) {
      throw new SyntaxError('hash is required')
    }

    this.hash = new Algorithm(this.hash)
  }
}

/**
 * Export
 */
module.exports = RsaHashedKeyAlgorithm
