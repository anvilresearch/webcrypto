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
const Algorithm = require('../../src/dictionaries/Algorithm')

/**
 * Tests
 */
describe('Algorithm', () => {
  describe('constructor', () => {
    describe('with string "algorithm" argument', () => {
      it('should set instance name to argument value', () => {
        let algorithm = new Algorithm('RSASSA-PKCS1-v1_5')
        algorithm.name.should.equal('RSASSA-PKCS1-v1_5')
      })
    })
    describe('with object "algorithm" argument', () => {
      it('should assign argument property values to instance', () => {
        let algorithm = new Algorithm({ name: 'RSASSA-PKCS1-v1_5' })
        algorithm.name.should.equal('RSASSA-PKCS1-v1_5')
      })

      it('should require algorithm name to be a string', () => {
        expect(() => {
          new Algorithm({ other: false })
        }).to.throw('Algorithm name must be a string')
      })
    })
  })
})
