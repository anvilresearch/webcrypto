/**
 * Module dependencies
 */
const SubtleCrypto = require('./SubtleCrypto')

/**
 * Crypto interface
 */
class Crypto {

  /**
   * getRandomValues
   */
  getRandomValues () {

  }

  /**
   * subtle
   */
  get subtle () {
    return new SubtleCrypto()
  }

}

/**
 * Export
 */
module.exports = Crypto
