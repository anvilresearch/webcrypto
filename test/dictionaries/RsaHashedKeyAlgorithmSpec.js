/**
 * Test dependencies
 */
const chai = require('chai')
const expect = chai.expect

/**
 * Assertions
 */
chai.should()

/**
 * Code under test
 */
const {
  RsaPrivateKey,
  RsaPrivateJwk,
  RsaPrivateCryptoKey,
  RsaPublicKey,
  RsaPublicJwk,
  RsaPublicCryptoKey
} = require('../RsaKeyPairForTesting')

const {TextEncoder} = require('text-encoding')
const crypto = require('../../src')
const CryptoKey = require('../../src/keys/CryptoKey')
const CryptoKeyPair = require('../../src/keys/CryptoKeyPair')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const RsaKeyAlgorithm = require('../../src/dictionaries/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../../src/dictionaries/RsaHashedKeyAlgorithm')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')

/**
 * Tests
 */
describe('RsaHashedKeyAlgorithm', () => {
})
