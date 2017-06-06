/**
 * Package dependencies
 */
const base64url = require('base64url')
const crypto = require('crypto')

/**
 * Local dependencies
 */
const CryptoKey = require('../keys/CryptoKey')
const JsonWebKey = require('../keys/JsonWebKey')
const KeyAlgorithm = require('./KeyAlgorithm')

/**
 * Errors
 */
const {
  DataError,
  OperationError,
  NotSupportedError,
  KeyFormatNotSupportedError
} = require('../errors')

/**
 * HmacKeyAlgorithm
 */
class HmacKeyAlgorithm extends KeyAlgorithm {
}

/**
 * Export
 */
module.exports = HmacKeyAlgorithm
