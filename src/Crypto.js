/**
 * Module dependencies
 */
const legacyCrypto = require('crypto')
const SubtleCrypto = require('./SubtleCrypto')
const {QuotaExceededError, TypeMismatchError} = require('./errors')

/**
 * integerTypes
 */
const integerTypes = [
  Int8Array,
  Uint8Array,
  Int16Array,
  Uint16Array,
  Int32Array,
  Uint32Array
]

/**
 * integerGetByConstructor
 */
const integerGetByConstructor = {
  'Int8Array': 'getInt8',
  'Uint8Array': 'getUint8',
  'Int16Array': 'getInt16',
  'Uint16Array': 'getUint16',
  'Int32Array': 'getInt32',
  'Uint32Array': 'getUint32'
}

/**
 * Crypto interface
 */
class Crypto {

  /**
   * getRandomValues
   */
  getRandomValues (typedArray) {
    if (!integerTypes.some(type => typedArray instanceof type)) {
      throw new TypeMismatchError()
    }

    let byteLength = typedArray.byteLength

    if (byteLength > 65536) {
      throw new QuotaExceededError()
    }

    let type = typedArray.constructor
    let method = integerGetByConstructor[type.name]
    let totalBytes = byteLength * typedArray.length
    let buffer = legacyCrypto.randomBytes(totalBytes)
    let arrayBuffer = new Uint8Array(buffer)
    let dataView = new DataView(arrayBuffer.buffer)

    for (let byteIndex = 0; byteIndex < totalBytes; byteIndex += byteLength) {
      let integer = dataView[method](byteIndex)
      let arrayIndex = byteIndex / byteLength
      typedArray[arrayIndex] = integer
    }

    return typedArray
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
