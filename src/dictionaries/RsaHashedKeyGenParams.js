'use strict'

/**
 * Local dependencies
 */
const RsaKeyGenParams = require('./RsaKeyGenParams')
const Algorithm = require('./Algorithm')

/**
 * RsaHashedKeyGenParams
 */
class RsaHashedKeyGenParams extends RsaKeyGenParams {

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
module.exports = RsaHashedKeyGenParams
