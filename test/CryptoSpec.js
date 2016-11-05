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
const crypto = require('../src')
const SubtleCrypto = require('../src/SubtleCrypto')

/**
 * Tests
 */
describe('Crypto', () => {
  describe('getRandomValues', () => {
    it('should return the typed array argument', () => {
      let array = new Uint8Array(16)
      crypto.getRandomValues(array).should.equal(array)
    })

    it('should write random values to the typed array', () => {
      let array = new Uint8Array(16)
      crypto.getRandomValues(array)
      array.forEach(value => value.should.not.equal(0))
    })
  })

  describe('subtle', () => {
    it('should return a SubtleCrypto instance', () => {
      crypto.subtle.should.be.instanceof(SubtleCrypto)
    })
  })
})
