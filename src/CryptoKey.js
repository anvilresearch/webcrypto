/**
 * CryptoKey interface
 */
class CryptoKey {

  /**
   * Constructor
   */
  constructor ({type, extractable, algorithm, usages}) {

    // ensure values are not writeable
    Object.defineProperties(this, {
      type: {
        enumerable: true,
        writeable: false,
        value: type
      },
      extractable: {
        enumerable: true,
        writeable: false,
        value: extractable
      },
      algorithm: {
        enumerable: true,
        writeable: false,
        value: algorithm
      },
      usages: {
        enumerable: true,
        writeable: false,
        value: usages
      }
    })

    //if (!Array.isArray(type) || KeyType.indexOf(type) === -1) { throw new Error('Invalid CryptoKey type') }
    // verify type of algorithm
    // verify type/enum of usages
  }
}

/**
 * Export
 */
module.exports = CryptoKey
