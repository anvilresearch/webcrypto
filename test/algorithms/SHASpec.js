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
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const ShaKeyAlgorithm = require('../../src/dictionaries/ShaKeyAlgorithm')
const SHA = require('../../src/algorithms/SHA')
const OperationError = require('../../src/errors/OperationError')

/**
 * Tests
 */
describe('SHA', () => {
  describe('dictionaries getter', () => {
    it('should return an array', () => {
      SHA.dictionaries.should.eql([
        KeyAlgorithm,
        ShaKeyAlgorithm
      ])
    })
  })

  describe('members getter', () => {
    it('should return an object', () => {
      SHA.members.should.eql({})
    })
  })

  describe('digest', () => {
    it('should return an ArrayBuffer', () => {
      let algorithm = { name: 'SHA-256' }
      let data = new TextEncoder().encode('return an ArrayBuffer')
      let sha = new SHA(algorithm)
      let result = sha.digest(algorithm, data)
      result.should.be.instanceof(ArrayBuffer)
    })

    it('should return a SHA-1 digest', () => {
      let algorithm = { name: 'SHA-1' }
      let data = new TextEncoder().encode('created with webcrypto in Chrome')
      let digest = new Uint8Array([
        240, 245, 162, 97, 158, 225, 111, 59, 198, 40,
        103, 60, 84, 159, 139, 205, 10, 116, 39, 41
      ])
      let sha = new SHA(algorithm)
      let result = sha.digest(algorithm, data)
      Buffer.from(result).should.eql(Buffer.from(digest.buffer))
    })

    it('should return a SHA-256 digest', () => {
      let algorithm = { name: 'SHA-256' }
      let data = new TextEncoder().encode('created with webcrypto in Chrome')
      let digest = new Uint8Array([
        34, 103, 130, 78, 94, 197, 88, 55, 100, 33, 101,
        214, 153, 38, 251, 0, 246, 42, 150, 222, 243, 57,
        184, 244, 74, 187, 55, 10, 206, 17, 146, 65
      ])
      let sha = new SHA(algorithm)
      let result = sha.digest(algorithm, data)
      Buffer.from(result).should.eql(Buffer.from(digest.buffer))
    })

    it('should return a SHA-384 digest', () => {
      let algorithm = { name: 'SHA-384' }
      let data = new TextEncoder().encode('created with webcrypto in Chrome')
      let digest = new Uint8Array([
        114, 126, 90, 78, 53, 164, 76, 208, 239, 167, 250, 77,
        174, 115, 146, 12, 35, 96, 15, 73, 222, 48, 186, 102,
        200, 91, 124, 153, 232, 76, 252, 143, 50, 251, 81, 152,
        45, 189, 41, 167, 139, 29, 52, 9, 140, 197, 5, 238
      ])
      let sha = new SHA(algorithm)
      let result = sha.digest(algorithm, data)
      Buffer.from(result).should.eql(Buffer.from(digest.buffer))
    })

    it('should return a SHA-512 digest', () => {
      let algorithm = { name: 'SHA-512' }
      let data = new TextEncoder().encode('created with webcrypto in Chrome')
      let digest = new Uint8Array([
        101, 55, 12, 162, 223, 251, 198, 26, 154, 74, 173, 61,
        47, 45, 191, 105, 49, 36, 189, 141, 96, 145, 253, 102,
        28, 145, 34, 244, 192, 232, 147, 88, 251, 73, 145, 241,
        204, 213, 77, 129, 119, 107, 197, 94, 204, 57, 20, 153,
        181, 113, 113, 50, 249, 134, 126, 99, 254, 190, 84, 124,
        180, 216, 176, 112
      ])
      let sha = new SHA(algorithm)
      let result = sha.digest(algorithm, data)
      Buffer.from(result).should.eql(Buffer.from(digest.buffer))
    })

    it('should throw an OperationError with unknown algorithm', () => {
      let algorithm = { name: 'SHA-UNKNOWN' }
      let data = new TextEncoder().encode('I am undigestable')
      let sha = new SHA(algorithm)
      expect(() => {
        sha.digest(algorithm, data)
      }).to.throw('SHA-UNKNOWN is not a supported algorithm')
    })
  })
})
