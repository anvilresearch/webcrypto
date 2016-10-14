/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.should()

/**
 * Code under test
 */
const recognizedKeyUsages = require('../../src/keys/recognizedKeyUsages')
const KeyUsage = recognizedKeyUsages.constructor

/**
 * Tests
 */
describe('recognizedKeyUsages', () => {

  /**
   * constructor
   */
  describe('constructor', () => {
    it('should initialize the list', () => {
      let usages = new KeyUsage(['sign', 'verify'])
      usages.should.include('sign')
      usages.should.include('verify')
      usages.length.should.equal(2)
    })
  })

  /**
   * normalize
   */
  describe('normalize', () => {
    let normalized

    before(() => {
      normalized = recognizedKeyUsages.normalize(['foo', 'sign', 'bar', 'verify'])
    })

    it('should include recognized usages', () => {
      normalized.should.include('sign')
      normalized.should.include('verify')
    })

    it('should ignore unknown usages', () => {
      normalized.should.not.include('foo')
      normalized.should.not.include('bar')
    })
  })
})
