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
const HMAC = require('../../src/algorithms/HMAC')
const OperationError = require('../../src/errors/OperationError')

/**
 * Tests
 */
describe('HMAC', () => {
  describe('dictionaries getter', () => {
    it('should return an array', () => {
      HMAC.dictionaries.should.eql([
        KeyAlgorithm,
        HmacKeyAlgorithm
      ])
    })
  })

  describe('members getter', () => {
    it('should return an object', () => {
      HMAC.members.should.eql({})
    })
  })

  describe('sign', () => {
    let alg, rawHmacKey, chromeHmacSignature, data, importedHmacKey

    before(() => {
      alg = { name: 'HMAC', hash: { name: 'SHA-256' } }

      rawHmacKey = new Uint8Array([
        137, 35, 38, 29, 130, 138, 121, 216, 20, 204, 169,
        61, 76, 80, 127, 140, 197, 193, 48, 6, 207, 97, 70,
        77, 57, 30, 72, 245, 249, 9, 204, 207, 215, 1, 53,
        33, 189, 28, 105, 9, 61, 158, 152, 113, 46, 83, 3,
        228, 234, 140, 20, 31, 192, 34, 254, 113, 117, 59,
        17, 78, 164, 52, 116, 38
      ])

      chromeHmacSignature = new Uint8Array([
        72, 73, 12, 66, 105, 131, 73, 116, 160, 243, 96, 121,
        121, 40, 244, 198, 107, 151, 113, 243, 51, 19, 60, 234,
        93, 23, 199, 14, 42, 118, 25, 161
      ])

      data = new TextEncoder()
        .encode('signed with Chrome generated webcrypto key')

      return crypto.subtle
        .importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
        .then(cryptoKey => importedHmacKey = cryptoKey)
    })

    it('should return an ArrayBuffer', () => {
      let hmac = new HMAC(alg)
      hmac.sign(importedHmacKey, data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a HMAC signature', () => {
      let hmac = new HMAC(alg)
      let signature = hmac.sign(importedHmacKey, data)
      Buffer.from(signature).should.eql(Buffer.from(chromeHmacSignature.buffer))
    })
  })

  describe('verify', () => {
    let alg, rawHmacKey, chromeHmacSignature, data, importedHmacKey

    before(() => {
      alg = { name: 'HMAC', hash: { name: 'SHA-256' } }

      rawHmacKey = new Uint8Array([
        137, 35, 38, 29, 130, 138, 121, 216, 20, 204, 169,
        61, 76, 80, 127, 140, 197, 193, 48, 6, 207, 97, 70,
        77, 57, 30, 72, 245, 249, 9, 204, 207, 215, 1, 53,
        33, 189, 28, 105, 9, 61, 158, 152, 113, 46, 83, 3,
        228, 234, 140, 20, 31, 192, 34, 254, 113, 117, 59,
        17, 78, 164, 52, 116, 38
      ])

      chromeHmacSignature = new Uint8Array([
        72, 73, 12, 66, 105, 131, 73, 116, 160, 243, 96, 121,
        121, 40, 244, 198, 107, 151, 113, 243, 51, 19, 60, 234,
        93, 23, 199, 14, 42, 118, 25, 161
      ])

      data = new TextEncoder()
        .encode('signed with Chrome generated webcrypto key')

      return crypto.subtle
        .importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
        .then(cryptoKey => importedHmacKey = cryptoKey)
    })

    it('should verify a valid HMAC signature', () => {
      let hmac = new HMAC(alg)
      hmac.verify(importedHmacKey, chromeHmacSignature, data).should.be.true
    })

    it('should not verify an invalid HMAC signature', () => {
      let hmac = new HMAC(alg)
      let invalidData = new TextEncoder().encode('wrong data')
      hmac.verify(importedHmacKey, chromeHmacSignature, invalidData).should.be.false
    })
  })

  describe('generateKey', () => {
    let alg, hmac, key

    beforeEach(() => {
      alg = { name: 'HMAC', hash: { name: 'SHA-256' } }
      hmac = new HMAC(alg)
      key = hmac.generateKey(alg, true, ['sign', 'verify'])
    })

    it('should throw with invalid usages', () => {
      expect(() => {
        hmac.generateKey(alg, true, ['sign', 'verify', 'wrong'])
      }).to.throw('Key usages can only include "sign" and "verify"')
    })

    it('should throw with invalid length', () => {
      expect(() => {
        hmac.generateKey({
          name: 'HMAC',
          hash: {
            name: 'SHA-256'
          },
          length: 0
        }, true, ['sign', 'verify'])
      }).to.throw('Invalid HMAC length')
    })

    it('should return CryptoKey', () => {
      key.should.be.instanceof(CryptoKey)
    })

    it('should set key type', () => {
      key.type.should.equal('secret')
    })

    it('should set key algorithm', () => {
      key.algorithm.should.be.instanceof(HMAC)
    })

    it('should set key algorithm name', () => {
      key.algorithm.name.should.equal('HMAC')
    })

    it('should set key algorithm hash', () => {
      key.algorithm.hash.should.be.instanceof(KeyAlgorithm)
    })

    it('should set key algorithm hash name', () => {
      key.algorithm.hash.name.should.equal('SHA-256')
    })

    it('should set key extractable', () => {
      key.extractable.should.equal(true)
    })

    it('should set key usages', () => {
      key.usages.should.eql(['sign', 'verify'])
    })

    it('should set key handle', () => {
      key.handle.should.be.instanceof(Buffer)
    })
  })

  describe('importKey', () => {
    let alg, hmac, rawHmacKey, key

    beforeEach(() => {
      alg = { name: 'HMAC', hash: { name: 'SHA-256' } }
      hmac = new HMAC(alg)

      rawHmacKey = new Uint8Array([
        137, 35, 38, 29, 130, 138, 121, 216, 20, 204, 169,
        61, 76, 80, 127, 140, 197, 193, 48, 6, 207, 97, 70,
        77, 57, 30, 72, 245, 249, 9, 204, 207, 215, 1, 53,
        33, 189, 28, 105, 9, 61, 158, 152, 113, 46, 83, 3,
        228, 234, 140, 20, 31, 192, 34, 254, 113, 117, 59,
        17, 78, 164, 52, 116, 38
      ])

      key = hmac.importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
    })

    it('should throw with invalid usages', () => {
      expect(() => {
        hmac.importKey('raw', rawHmacKey, alg, true, ['sign', 'verify', 'wrong'])
      }).to.throw('Key usages can only include "sign" and "verify"')
    })

    it('should throw with missing algorithm hash', () => {
      expect(() => {
        alg = { name: 'HMAC' }
        hmac.importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
      }).to.throw('HmacKeyGenParams: hash: Missing or not an AlgorithmIdentifier')
    })

    it('should throw with unsupported key format', () => {
      expect(() => {
        hmac.importKey('WRONG', rawHmacKey, alg, true, ['sign', 'verify'])
      }).to.throw('WRONG is not a supported key format')
    })

    it('should throw with empty key data', () => {
      expect(() => {
        hmac.importKey('raw', new Uint8Array(), alg, true, ['sign', 'verify'])
      }).to.throw('HMAC key data must not be empty')
    })

    it('should import raw key data and return a CryptoKey', () => {
      hmac.importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
        .should.be.instanceof(CryptoKey)
    })

    it('should set key type', () => {
      hmac.importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
        .type.should.equal('secret')
    })

    it('should set key algorithm', () => {
      hmac.importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
        .algorithm.should.be.instanceof(HMAC)
    })

    it('should set key algorithm name', () => {
      key.algorithm.name.should.equal('HMAC')
    })

    it('should set key algorithm hash name', () => {
      key.algorithm.hash.name.should.equal('SHA-256')
    })

    it('should set key extractable', () => {
      key.extractable.should.equal(true)
    })

    it('should set key usages', () => {
      key.usages.should.eql(['sign', 'verify'])
    })

    it('should set key handle', () => {
      key.handle.should.be.instanceof(Buffer)
    })
  })

  describe('exportKey', () => {
    let alg, hmac, rawHmacKey, key

    beforeEach(() => {
      alg = { name: 'HMAC', hash: { name: 'SHA-256' } }
      hmac = new HMAC(alg)

      rawHmacKey = new Uint8Array([
        137, 35, 38, 29, 130, 138, 121, 216, 20, 204, 169,
        61, 76, 80, 127, 140, 197, 193, 48, 6, 207, 97, 70,
        77, 57, 30, 72, 245, 249, 9, 204, 207, 215, 1, 53,
        33, 189, 28, 105, 9, 61, 158, 152, 113, 46, 83, 3,
        228, 234, 140, 20, 31, 192, 34, 254, 113, 117, 59,
        17, 78, 164, 52, 116, 38
      ])

      key = hmac.importKey('raw', rawHmacKey, alg, true, ['sign', 'verify'])
    })

    it('should throw with invalid usages', () => {
      expect(() => {
        hmac.exportKey('raw', {})
      }).to.throw('argument must be CryptoKey')
    })

    it('should throw with unsupported key format', () => {
      expect(() => {
        hmac.exportKey('WRONG', key)
      }).to.throw('WRONG is not a supported key format')
    })

    it('should return a raw key', () => {
      hmac.exportKey('raw', key).should.be.instanceof(Buffer)
    })
  })
})
