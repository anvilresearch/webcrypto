/**
 * CryptoKeyPair dictionary
 */
class CryptoKeyPair {
  constructor ({publicKey,privateKey}) {
    this.publicKey = publicKey
    this.privateKey = privateKey
  }
}

/**
 * Export
 */
module.exports = CryptoKeyPair

