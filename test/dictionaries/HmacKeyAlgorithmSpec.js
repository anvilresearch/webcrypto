/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.should()
const expect = chai.expect

/**
 * Code under test
 */
const {TextEncoder} = require('text-encoding')
const crypto = require('../../src')
const CryptoKey = require('../../src/keys/CryptoKey')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const HmacKeyAlgorithm = require('../../src/dictionaries/HmacKeyAlgorithm')
const OperationError = require('../../src/errors/OperationError')

/**
 * Tests
 */
describe('HmacKeyAlgorithm', () => {
})
