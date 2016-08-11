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
const RegisteredAlgorithms = require('../../src/algorithms/RegisteredAlgorithms')

/**
 * Tests
 */
describe('RegisteredAlgorithms', () => {
  describe('constructor', () => {
    it('should assign object argument properties', () => {
      let registeredAlgorithms = new RegisteredAlgorithms({ a: 1, b: 2 })
      registeredAlgorithms.should.eql({ a: 1, b: 2 })
    })
  })

  describe('getCaseInsensitive', () => {
    let registeredAlgorithms

    beforeEach(() => {
      registeredAlgorithms = new RegisteredAlgorithms({
        'RSASSA-PKCS1-v1_5': {}
      })
    })

    it('should match a known property with exact case', () => {
      registeredAlgorithms
        .getCaseInsensitive('RSASSA-PKCS1-v1_5')
        .should.equal('RSASSA-PKCS1-v1_5')
    })

    it('should match a known property with different case', () => {
      registeredAlgorithms
        .getCaseInsensitive('rsassa-pkcs1-v1_5')
        .should.equal('RSASSA-PKCS1-v1_5')
    })

    it('should return "undefined" with no match', () => {
      expect(registeredAlgorithms.getCaseInsensitive('unknown')).to.be.undefined
    })
  })
})
