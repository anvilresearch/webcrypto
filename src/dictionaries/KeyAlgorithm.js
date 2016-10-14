/**
 * Local dependencies
 */
const {NotSupportedError} = require('../errors')

/**
 * KeyAlgorithm dictionary
 */
class KeyAlgorithm {

  /**
   * constructor
   *
   * @param {object} algorithm
   */
  constructor (algorithm) {
    Object.assign(this, algorithm)

    // validate name
    if (this.name === undefined) {
      throw new Error('KeyAlgorithm must have a name')
    }
  }

  /**
   * TODO
   * If we split algorithm implementations away from dictionaries,
   * we'll need to remove these abstract methods.
   *
   * It seems that SupportedAlgorithms covers the same ground of
   * throwing a NotSupportedError, and these would never be invoked.
   */

  /**
   * encrypt
   *
   * @description
   * encrypt is not a supported operation for this algorithm.
   */
  encrypt () {
    throw new NotSupportedError()
  }

  /**
   * decrypt
   *
   * @description
   * decrypt is not a supported operation for this algorithm.
   */
  decrypt () {
    throw new NotSupportedError()
  }

  /**
   * sign
   *
   * @description
   * sign is not a supported operation for this algorithm.
   */
  sign () {
    throw new NotSupportedError()
  }

  /**
   * verify
   *
   * @description
   * verify is not a supported operation for this algorithm.
   */
  verify () {
    throw new NotSupportedError()
  }

  /**
   * deriveBits
   *
   * @description
   * deriveBits is not a supported operation for this algorithm.
   */
  deriveBits () {
    throw new NotSupportedError()
  }

  /**
   * wrapKey
   *
   * @description
   * wrapKey is not a supported operation for this algorithm.
   */
  wrapKey () {
    throw new NotSupportedError()
  }

  /**
   * unwrapKey
   *
   * @description
   * unwrapKey is not a supported operation for this algorithm.
   */
  unwrapKey () {
    throw new NotSupportedError()
  }

  /**
   * generateKey
   *
   * @description
   * generateKey is not a supported operation for this algorithm.
   */
  generateKey () {
    throw new NotSupportedError()
  }

  /**
   * importKey
   *
   * @description
   * @param {}
   * @returns {}
   */
  importKey () {
    throw new NotSupportedError()
  }

  /**
   * exportKey
   *
   * @description
   * @param {}
   * @returns {}
   */
  exportKey () {
    throw new NotSupportedError()
  }

  /**
   * getLength
   *
   * @description
   * getLength is not a supported operation for this algorithm.
   */
  getLength () {
    throw new NotSupportedError()
  }
}

/**
 * Export
 */
module.exports = KeyAlgorithm
