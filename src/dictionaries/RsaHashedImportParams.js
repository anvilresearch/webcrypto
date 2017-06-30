'use strict'

/**
 * Local dependencies
 */
const Algorithm = require('./Algorithm')

/**
 * RsaHashedImportParams
 */
class RsaHashedImportParams extends Algorithm {

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
module.exports = RsaHashedImportParams
