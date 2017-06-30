'use strict'

/**
 * BigInteger
 *
 * @typedef {BigInteger} Uint8Array
 *
 * @description
 * The BigInteger typedef is a Uint8Array that holds an arbitrary magnitude unsigned integer in
 * big-endian order. Values read from the API SHALL have minimal typed array length (that is, at
 * most 7 leading zero bits, except the value 0 which shall have length 8 bits). The API SHALL
 * accept values with any number of leading zero bits, including the empty array, which represents
 * zero.
 */

/**
 * Dictionary
 */
class Dictionary {

  constructor (algorithm) {
    if (typeof algorithm === 'string') {
      this.name = algorithm
    } else {
      Object.assign(this, algorithm)
    }
  }

  static roundTowardZero (value) {
    if (value >= 0) {
      return Math.floor(value)
    } else {
      return Math.ceil(value)
    }
  }

  static coerceNumber (value, type) {
    switch (type) {
      case 'byte':
        if (value < -128) {
          return -128
        } else if (value > 127) {
          return 127
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'octet':
        if (value > 255) {
          return 255
        } else if (value < 0) {
          return 0
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'short':
        if (value > 32767) {
          return 32767
        } else if (value < -32768) {
          return -32768
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'unsigned short':
        if (value > 66535) {
          return 65535
        } else if (value < 0) {
          return 0
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'long':
        if (value > 2147483647) {
          return 2147483647
        } else if (value < -2147483648) {
          return -2147483648
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'unsigned long':
        if (value > 4294967295) {
          return 4294967295
        } else if (value < 0) {
          return 0
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'long long':
        if (value > 9223372036854775807) {
          return 9223372036854775807
        } else if (value < -9223372036854775808) {
          return -9223372036854775808
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'unsigned long long':
        if (value > 18446744073709551615) {
          return 18446744073709551615
        } else if (value < 0) {
          return 0
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'float':
        return Number(value)

      case 'double':
        return Number(value)

      default:
        throw new TypeError(`Invalid type ${type}`)
    }
  }

  static enforceRange (value, type) {
    switch (type) {
      case 'byte':
        if (value < -128) {
          throw new TypeError('Value out of range')
        } else if (value > 127) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'octet':
        if (value > 255) {
          throw new TypeError('Value out of range')
        } else if (value < 0) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'short':
        if (value > 32767) {
          throw new TypeError('Value out of range')
        } else if (value < -32768) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'unsigned short':
        if (value > 66535) {
          throw new TypeError('Value out of range')
        } else if (value < 0) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'long':
        if (value > 2147483647) {
          throw new TypeError('Value out of range')
        } else if (value < -2147483648) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'unsigned long':
        if (value > 4294967295) {
          throw new TypeError('Value out of range')
        } else if (value < 0) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'long long':
        if (value > 9223372036854775807) {
          throw new TypeError('Value out of range')
        } else if (value < -9223372036854775808) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      case 'unsigned long long':
        if (value > 18446744073709551615) {
          throw new TypeError('Value out of range')
        } else if (value < 0) {
          throw new TypeError('Value out of range')
        } else {
          return Algorithm.roundTowardZero(value)
        }

      default:
        throw new TypeError(`Invalid type ${type}`)
    }
  }
}

/**
 * Export
 * @ignore
 */
module.exports = Dictionary
