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
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const NotSupportedError = require('../../src/errors/NotSupportedError')

/**
 * Tests
 */
describe('KeyAlgorithm', () => {
  describe('constructor', () => { 
    it('should assign argument property values to instance', () => {
      let keyAlgorithm = new KeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
      keyAlgorithm.name.should.equal('RSASSA-PKCS1-v1_5')
    })

    it('should require algorithm name', () => {
      expect(() => {
        new KeyAlgorithm({ other: false })
      }).to.throw('KeyAlgorithm must have a name')
    })
  })
})
