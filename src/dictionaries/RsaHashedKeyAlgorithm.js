/**
 * Package dependencies
 */
const RSA = require('node-rsa')
const crypto = require('crypto')
const {spawnSync} = require('child_process')
const {pem2jwk, jwk2pem} = require('pem-jwk')
const {TextEncoder, TextDecoder} = require('text-encoding')

/**
 * Local dependencies
 */
const CryptoKey = require('../keys/CryptoKey')
const CryptoKeyPair = require('../keys/CryptoKeyPair')
const JsonWebKey = require('../keys/JsonWebKey')
const KeyAlgorithm = require('./KeyAlgorithm')
const RsaKeyAlgorithm = require('./RsaKeyAlgorithm')
const supportedAlgorithms = require('../algorithms')

/**
 * Errors
 */
const {
  DataError,
  OperationError,
  InvalidAccessError,
  KeyFormatNotSupportedError
} = require('../errors')

/**
 * RsaHashedKeyAlgorithm
 */
class RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {

}

/**
 * Export
 */
module.exports = RsaHashedKeyAlgorithm
