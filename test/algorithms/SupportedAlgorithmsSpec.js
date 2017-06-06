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
const supportedAlgorithms = require('../../src/algorithms')
const SupportedAlgorithms = require('../../src/algorithms/SupportedAlgorithms')
const RegisteredAlgorithms = require('../../src/algorithms/RegisteredAlgorithms')
const RSASSA_PKCS1_v1_5 = require('../../src/algorithms/RSASSA-PKCS1-v1_5')
const SHA               = require('../../src/algorithms/SHA')
const NotSupportedError = require('../../src/errors/NotSupportedError')

/**
 * Tests
 */
describe('SupportedAlgorithms', () => {

  /**
   * Constructor
   */
  describe('constructor', () => {
    it('should initialize a container for each operation', () => {
      let operations = SupportedAlgorithms.operations

      operations.forEach(op => {
        supportedAlgorithms[op].should.be.instanceof(RegisteredAlgorithms)
      })
    })
  })

  /**
   * Operations
   */
  describe('operations', () => {
    it('should include specified operations', () => {
      let operations = SupportedAlgorithms.operations
      operations.should.include('encrypt')
      operations.should.include('decrypt')
      operations.should.include('sign')
      operations.should.include('verify')
      operations.should.include('deriveBits')
      operations.should.include('wrapKey')
      operations.should.include('unwrapKey')
      operations.should.include('generateKey')
      operations.should.include('importKey')
      operations.should.include('exportKey')
      operations.should.include('getLength')
    })
  })

  /**
   * Define
   */
  describe('define', () => {
    it('should registered a type for an operation of an algorithm', () => {
      class Dictionary {}
      let alg = 'FAKE'
      supportedAlgorithms.define(alg, 'sign', Dictionary)
      supportedAlgorithms.sign[alg].should.equal(Dictionary)
    })
  })

  /**
   * Normalize
   */
  describe('normalize', () => {
    describe('with string "alg" argument', () => {
      describe('unknown algorithm', () => {
        let normalizedAlgorithm

        before(() => {
          normalizedAlgorithm = supportedAlgorithms.normalize('sign', 'UNKNOWN')
        })

        it('should return an error', () => {
          normalizedAlgorithm.should.be.instanceof(NotSupportedError)
        })
      })

      describe('valid algorithm', () => {
        let normalizedAlgorithm

        before(() => {
          normalizedAlgorithm = supportedAlgorithms.normalize('digest', 'SHA-256')
        })

        it('should return the normalized algorithm', () => {
          normalizedAlgorithm.should.be.instanceof(SHA)
        })
      })
    })

    describe('with object "alg" argument', () => {
      describe('invalid "name"', () => {
        let normalizedAlgorithm

        before(() => {
          normalizedAlgorithm = supportedAlgorithms.normalize('sign', {})
        })

        it('should return an error', () => {
          normalizedAlgorithm.should.be.instanceof(Error)
        })
      })

      describe('unknown algorithm', () => {
        let normalizedAlgorithm

        before(() => {
          normalizedAlgorithm = supportedAlgorithms.normalize('sign', {
            name: 'UNKNOWN'
          })
        })

        it('should return a NotSupportedError', () => {
          normalizedAlgorithm.should.be.instanceof(NotSupportedError)
        })
      })

      describe('invalid param', () => {
        it('should return an error')
      })

      describe('valid params', () => {
        let normalizedAlgorithm

        before(() => {
          normalizedAlgorithm = supportedAlgorithms.normalize('generateKey', {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: 'SHA-1'
          })
        })

        it('should return the normalized algorithm', () => {
          normalizedAlgorithm.should.be.instanceof(RSASSA_PKCS1_v1_5)
        })
      })
    })
  })

  /**
   * Default registration
   */
  describe('default registration', () => {})
})
