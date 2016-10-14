/**
 * CryptoKey interface
 */
class CryptoKey {

  /**
   * Constructor
   */
  constructor ({type, extractable, algorithm, usages, handle}) {
    this.type = type
    this.extractable = extractable
    this.algorithm = algorithm
    this.usages = usages

    // ensure values are not writeable
    Object.defineProperties(this, {
      // TODO
      // These properties can't be fixed immediately on creation of the
      // object because the implementation may build it up in stages.
      // At some point in the operations before returning a key we should
      // freeze the object to prevent further manipulation.

      //type: {
      //  enumerable: true,
      //  writeable: false,
      //  value: type
      //},
      //extractable: {
      //  enumerable: true,
      //  writeable: true,
      //  value: extractable
      //},
      //algorithm: {
      //  enumerable: true,
      //  writeable: false,
      //  value: algorithm
      //},
      //usages: {
      //  enumerable: true,
      //  writeable: true,
      //  value: usages
      //},

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

  /**
   * Structured clone algorithm
   * https://www.w3.org/TR/WebCryptoAPI/#cryptokey-interface-clone
   *
   * TODO
   * This requires review and consideration with respect to the
   * internal structured cloning algorithm.
   * https://www.w3.org/TR/WebCryptoAPI/#dfn-structured-clone
   *
   * @param {Object} input
   * @param {Object} memory
   *
   * @returns {CryptoKey}
   */
  clone ({type,extractable,algorithm,usages,handle}, memory) {
    return new CryptoKey({type,extractable,algorithm,usages,handle})
  }
}

/**
 * Export
 */
module.exports = CryptoKey
