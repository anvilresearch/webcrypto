/**
 * Package dependencies
 */
const crypto = require('crypto')
const RSA = require('node-rsa')

/**
 * Local dependencies
 */
const Algorithm = require('../Algorithm')
const BigInteger = require('../BigInteger')
const CryptoKeyPair = require('../CryptoKeyPair')
const HashAlgorithmIdentifier = require('../HashAlgorithmIdentifier')
const KeyAlgorithm = require('../KeyAlgorithm')

/**
 * RsaKeyGenParams
 */
class RsaKeyGenParams extends Algorithm {
  constructor (modulusLength, publicExponent) {
    // validate and set modulusLength
    if (typeof modulusLength !== 'number') { throw new Error() }
    if (modulusLength < 1024) { throw new Error() }
    this.modulusLength = modulusLength

    // validate and set publicExponent
    if (!(publicExponent instanceof BigInteger)) { throw new Error() }
    this.publicExponent = publicExponent
  }
}

/**
 * RsaHashedKeyGenParams
 */
class RsaHashedKeyGenParams extends RsaKeyGenParams {
  constructor (modulusLength, publicExponent, hash) {
    super(modulusLength, publicExponent)

    // validate and set hash
    if (!(hash instanceof HashAlgorithmIdentifier)) { throw new Error() }
    this.hash = hash
  }
}

/**
 * RsaKeyAlgorithm
 */
class RsaKeyAlgorithm extends KeyAlgorithm {
  constructor (modulusLength, publicExponent) {
    // validate and set modulusLength
    if (typeof modulusLength !== 'number') { throw new Error() }
    if (modulusLength < 1024) { throw new Error() }
    this.modulusLength = modulusLength

    // validate and set publicExponent
    if (!(publicExponent instanceof BigInteger)) { throw new Error() }
    this.publicExponent = publicExponent
  }
}

/**
 * RsaHashedKeyAlgorithm
 */
class RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {
  constructor (modulusLength, publicExponent, hash) {
    super(modulusLength, publicExponent)

    // validate and set hash
    if (!(hash instanceof KeyAlgorithm)) { throw new Error() }
    this.hash = hash
  }
}

/**
 * RsaHashedImportParams
 */
class RsaHashedImportParams {
  constructor (hash) {
    // validate and set hash
    if (!(hash instanceof HashAlgorithmIdentifier)) { throw new Error() }
    this.hash = hash
  }
}

/**
 * RSASSA-PKCS1-v1_5
 */
class RSASSA-PKCS1-v1_5 {

  /**
   * Constuctor
   */
  constructor (key, data, bitlength) {
    // TODO should name be an argument to constructor?
    this.name = 'RSASSA-PKCS1-v1_5'
    this.key = key
    this.data = data
    this.bitlength = bitlength
  }

  /**
   * exportKey
   */
  exportKey () {}

  /**
   * generateKey
   */
  generateKey () {
    let key = new RSA()

    // ...

    return new CryptoKeyPair()
  }

  /**
   * importKey
   */
  importKey () {}

  /**
   * signKey
   */
  sign (key, data) {

  }

  /**
   * verifyKey
   */
  verify () {}
}

/**
 * Export
 */
module.exports = RSASSA-PKCS1-v1_5
