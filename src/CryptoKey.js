/**
 * CryptoKey interface
 */
class CryptoKey {

  /**
   * Constructor
   */
  constructor ({type, extractable, algorithm, usages, handle}) {

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
      },

      // this is the "key material" used internally
      // it is not enumerable, but we need it to be
      // accessible by algorithm implementations
      handle: {
        enumerable: false,
        writeable: false,
        value: handle
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
