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
const {buf2ab,ab2buf,str2ab,ab2str} = require('../../src/encodings')

/**
 * Tests
 */
describe('encodings', () => {
  let result

  describe('buf2ab', () => {
    it('should convert a Buffer to an ArrayBuffer', () => {
      result = buf2ab(new Buffer('abc'))
      result.should.be.instanceof(ArrayBuffer)
    })
  })

  describe('ab2buf', () => {
    it('should convert an ArrayBuffer to a Buffer', () => {
      result = ab2buf(result)
      result.should.eql(new Buffer('abc'))
    })
  })

  describe('str2ab', () => {
    it('should convert a String to an ArrayBuffer', () => {
      result = str2ab('def')
      result.should.be.instanceof(ArrayBuffer)
    })
  })

  describe('ab2str', () => {
    it('should convert an ArrayBuffer to a String', () => {
      result = ab2str(result)
      result.should.equal('def')
    })
  })
})
