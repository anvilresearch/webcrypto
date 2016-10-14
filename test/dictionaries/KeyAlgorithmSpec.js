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

  describe('encrypt', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.encrypt()
      }).to.throw(NotSupportedError)
    })
  })

  describe('decrypt', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.decrypt()
      }).to.throw(NotSupportedError)
    })
  })

  describe('sign', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.sign()
      }).to.throw(NotSupportedError)
    })
  })

  describe('verify', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.verify()
      }).to.throw(NotSupportedError)
    })
  })

  describe('deriveBits', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.deriveBits()
      }).to.throw(NotSupportedError)
    })
  })

  describe('wrapKey', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.wrapKey()
      }).to.throw(NotSupportedError)
    })
  })

  describe('unwrapKey', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.unwrapKey()
      }).to.throw(NotSupportedError)
    })
  })

  describe('generateKey', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.generateKey()
      }).to.throw(NotSupportedError)
    })
  })

  describe('importKey', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.importKey()
      }).to.throw(NotSupportedError)
    })
  })

  describe('exportKey', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.exportKey()
      }).to.throw(NotSupportedError)
    })
  })

  describe('getLength', () => {
    it('should throw NotSupportedError', () => {
      expect(() => {
        let instance = new KeyAlgorithm({ name: 'ECDSA' })
        instance.getLength()
      }).to.throw(NotSupportedError)
    })
  })
})
