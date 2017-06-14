/**
 * Test dependencies
 */
const chai = require('chai')
const expect = chai.expect

/**
 * Assertions
 */
chai.should()

const {TextEncoder} = require('text-encoding')
const crypto = require('../../src')
const CryptoKey = require('../../src/keys/CryptoKey')
const CryptoKeyPair = require('../../src/keys/CryptoKeyPair')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const EcKeyAlgorithm = require('../../src/dictionaries/EcKeyAlgorithm')
const ECDSA = require('../../src/algorithms/ECDSA')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')
const CurrentlyNotSupportedError = require('../../src/errors/CurrentlyNotSupportedError')

/**
 * Code under test
 */
const {
  ECDSA_K256_PrivateKey,
  ECDSA_K256_PublicKey,
  ECDSA_K256_PrivatePem,
  ECDSA_K256_PublicPem,
} = require('../EcdsaKeyPairsForTesting')


/**
 * Tests
 */
describe('ECDSA', () => {
  /**
   * dictionaries getter
   */
  describe.skip('dictionaries getter', () => {
    it('should return an array', () => {
      ECDSA.dictionaries.should.eql([
        KeyAlgorithm,
        EcKeyAlgorithm
      ])
    })
  })

  /**
   * members getter
   */
    describe.skip('members getter', () => {
      it('should return an object', () => {
        ECDSA.members.hash.should.equal('HashAlgorithmIdentifier')
    })
  })

  /**
   * sign
   */
  describe('sign', () => {
    let alg, ecdsa, data, signature

    before(() => {
        alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } }
        ecdsa = new ECDSA(alg)
        
        data = new TextEncoder().encode('signed with elliptic.js module')
    })

    it('should throw with non-private key', () => {
      expect(() => {
        ecdsa.sign(ECDSA_K256_PublicKey, new Uint8Array())
      }).to.throw('Signing requires a private key')
    })

    it('should return an ArrayBuffer', () => {
      ecdsa.sign(ECDSA_K256_PrivateKey, data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a ECDSA signature')
  })

  /**
   * verify
   */
  describe('verify', () => {
    let alg, ecdsa, data, signature

    before(() => {
        alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } }
        ecdsa = new ECDSA(alg)

        data = new TextEncoder().encode('signed with elliptic.js module')
        
        signature =  new Uint8Array([ 48,  69,  2,  32,  123,  162,  50,  30,  164,  
            193,  22,  192,  115,  60,  235,  173,  129,  57,  80,  180,  96,  108,  
            102,  208,  213,  116,  102,  123,  87,  116,  212,  170,  221,  39,  
            165,  154,  2,  33,  0,  205,  67,  50,  237,  235,  121,  114,  98,  
            126,  199,  100,  211,  15,  185,  46,  113,  242,  198,  50,  162,  
            223,  250, 240,  82,  80,  230,  146,  175,  115,  156,  199,  213 ])
    })
    
    it('should throw with non-private key', () => {
      expect(() => {
        ecdsa.verify(ECDSA_K256_PrivateKey, new Uint8Array())
      }).to.throw('Verifying requires a public key')
    })

    it.skip('should return true with valid signature', () => { 
      ecdsa.verify(ECDSA_K256_PublicKey, signature, data).should.equal(true)
    })

    it('should return false with invalid signature', () => {
      let invalidData = new TextEncoder().encode('invalid signature')
      ecdsa.verify(ECDSA_K256_PublicKey, signature, invalidData).should.equal(false)
    })
  })
  /**
   * generateKey
   */
  describe('generateKey', () => {
    let alg, ecdsa, cryptoKeyPair

    before(() => {
      alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' }}
      ecdsa = new ECDSA(alg)
      return Promise.resolve()
        .then(() => cryptoKeyPair = ecdsa.generateKey(alg, true, ['sign', 'verify']))

    })

    it('should throw with invalid usages', () => {
      expect(() => {
        ecdsa.generateKey(alg, true, ['sign', 'verify', 'wrong'])
      }).to.throw('Key usages can only include "sign", or "verify"')
    })

    it('should return CryptoKey', () => {
      cryptoKeyPair.should.be.instanceof(CryptoKeyPair)
    })

    it('should set public key type', () => {
      cryptoKeyPair.publicKey.type.should.equal('public')
    })

    it('should set private key type', () => {
      cryptoKeyPair.privateKey.type.should.equal('private')
    })

    it('should set public key algorithm', () => {
      cryptoKeyPair.publicKey.algorithm
        .should.be.instanceof(ECDSA)
    })

    it('should set private key algorithm', () => {
      cryptoKeyPair.privateKey.algorithm
        .should.be.instanceof(ECDSA)
    })

    it('should set public key algorithm name', () => {
      cryptoKeyPair.publicKey.algorithm.name
        .should.equal('ECDSA')
    })

    it('should set private key algorithm name', () => {
      cryptoKeyPair.privateKey.algorithm.name
        .should.equal('ECDSA')
    })

    it('should set public key algorithm hash name', () => {
      cryptoKeyPair.publicKey.algorithm.hash.name
        .should.equal('SHA-256')
    })

    it('should set private key algorithm hash name', () => {
      cryptoKeyPair.privateKey.algorithm.hash.name
        .should.equal('SHA-256')
    })

    it('should set public key extractable', () => {
      cryptoKeyPair.publicKey.extractable.should.equal(true)
    })

    it('should set private key extractable', () => {
      cryptoKeyPair.privateKey.extractable.should.equal(true)
    })

    it('should set public key usages', () => {
      cryptoKeyPair.publicKey.usages.should.eql(['verify'])
    })

    it('should set private key usages', () => {
      cryptoKeyPair.privateKey.usages.should.eql(['sign'])
    })

    it('should set public key handle', () => {
      cryptoKeyPair.publicKey.handle
        .should.include('-----BEGIN PUBLIC KEY-----')
    })

    it('should set private key handle', () => {
      cryptoKeyPair.privateKey.handle
        .should.include('-----BEGIN EC PRIVATE KEY-----')
    })
  })

  /**
   * importKey
   */
   describe('importKey', () => {
    describe('with "spki" format', () => {})
    describe('with "pkcs8 format"', () => {})
    describe('with "jwk" format', () => {
      describe('private key and invalid usages', () => {
        let key, alg, ec

        before(() => {
          key = {
            kty: 'EC',
            crv: 'K-256',
            d: 'PR587JJiuSE3aFthaonYf3VJtB9WXaZcN7Vi0OmBUtw',
            x: 'L_yAQbK4Kg95AknFkfVO8V5rWkN1shsz7jrEyDZ3McA',
            y: '2Na7_YUSHDMn68XsnIGOfo3TwiIqfbaTXvavUKzT6qo'
          }
          ec = new ECDSA({ 
              name: 'ECDSA', 
              namedCurve: 'K-256', 
              hash: { name: 'SHA-256' } 
          })
          alg = { name: 'K-256' }
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            ec.importKey('jwk', key, alg , false, ['bad'])
          }).to.throw('Key usages must include "sign"')
        })
      })

      describe('non-private key and invalid usages', () => {
        let key, alg, ec

        before(() => {
          key = {
            kty: 'EC',
            crv: 'K-256',
            x: 'L_yAQbK4Kg95AknFkfVO8V5rWkN1shsz7jrEyDZ3McA',
            y: '2Na7_YUSHDMn68XsnIGOfo3TwiIqfbaTXvavUKzT6qo'
          }
          ec = new ECDSA({ 
              name: 'ECDSA', 
              namedCurve: 'K-256', 
              hash: { name: 'SHA-256' } 
          })
          alg = { name: 'K-256' }
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            ec.importKey('jwk', key, alg, false, ['bad'])
          }).to.throw('Key usages must include "verify"')
        })
      })

      describe('invalid key type', () => {
        let key, alg, ec

        before(() => {
          key = {
            kty: 'WRONG',
            crv: 'K-256',
            x: 'L_yAQbK4Kg95AknFkfVO8V5rWkN1shsz7jrEyDZ3McA',
            y: '2Na7_YUSHDMn68XsnIGOfo3TwiIqfbaTXvavUKzT6qo'
          }
          ec = new ECDSA({ 
              name: 'ECDSA', 
              namedCurve: 'K-256', 
              hash: { name: 'SHA-256' } 
            })
          alg = { name: 'K-256' }
        })

        it('should throw DataError', () => {
          expect(() => {
            ec.importKey('jwk', key, alg, false, ['verify'])
          }).to.throw('Key type must be "EC"')
        })
      })

      describe('invalid key use', () => {
        let key, alg, ec

        before(() => {
          key = {
            kty: 'EC',
            crv: 'K-256',
            x: 'L_yAQbK4Kg95AknFkfVO8V5rWkN1shsz7jrEyDZ3McA',
            y: '2Na7_YUSHDMn68XsnIGOfo3TwiIqfbaTXvavUKzT6qo',
            use: "WRONG"
          }
          ec = new ECDSA({ 
              name: 'ECDSA', 
              namedCurve: 'K-256', 
              hash: { name: 'SHA-256' } 
          })
          alg = { name: 'K-256' }
        })

        it('should throw DataError', () => {
          expect(() => {
            ec.importKey('jwk', key, alg, false, ['verify'])
          }).to.throw('Key use must be "sig".')
        })
      })

      describe('private K256 key', () => {
        let key

        before(() => {
          key = ECDSA_K256_PrivateKey
        })

        it('should define type', () => {
          key.type.should.equal('private')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(ECDSA)
        })

        it('should define extractable', () => {
          key.extractable.should.equal(true)
        })

        it('should define usages', () => {
          key.usages.should.eql(['sign'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN EC PRIVATE KEY-----')
        })
      })

      describe('public K256 key', () => {
        let key

        before(() => {
          key = ECDSA_K256_PublicKey
        })

        it('should define type', () => {
          key.type.should.equal('public')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(ECDSA)
        })

        it('should define extractable', () => {
          key.extractable.should.equal(true)
        })

        it('should define usages', () => {
          key.usages.should.eql(['verify'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN PUBLIC KEY-----')
        })
      })

      describe('with "raw" format', () => {})
    })

    describe('with other format', () => {
      it('should throw NotSupportedError', () => {
        let alg = new ECDSA({ name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } })

        let caller = () => {
          alg.importKey('WRONG', {}, alg, false, ['verify'])
        }

        expect(caller).to.throw(NotSupportedError)
        expect(caller).to.throw('is not a supported key format')
      })
    })
  })
  
  /**
   * exportKey
   */
  describe('exportKey', () => {
    describe('with missing key material', () => {
      it('should throw OperationError', () => {
        expect(() => {
          let ec = new ECDSA({ name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } })
          ec.exportKey('format', {})
        }).to.throw('Missing key material')
      })
    })

    describe('with "spki" format', () => {})
    describe('with "pkcs8 format"', () => {})

    describe('with "jwk" format', () => {
      describe('K-256 curve', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-256' } },
            extractable: true,
            usages: ['verify'],
            handle: ECDSA_K256_PublicPem
          })

          let ec = new ECDSA({ name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } })
          jwk = ec.exportKey('jwk', key)
        })
        it('should set "crv" to "K-256"', () => {
            jwk.crv.should.equal('K-256')
        })
      })
      describe('other hash', () => {})
    })
    describe('with "raw" format', () => {
     describe('K-256 curve', () => {
        let raw, key

        before(() => {
          key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-256' } },
            extractable: true,
            usages: ['verify'],
            handle: ECDSA_K256_PublicPem
          })

          let ec = new ECDSA({ name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } })
          raw = ec.exportKey('raw', key)
        })
        it('return the handle of CryptoKey', () => {
            raw.should.deep.equal(Buffer.from(key.handle))
        })
      })
    })
    describe('with other format', () => {
      it('should throw NotSupportedError', () => {
        let key = new CryptoKey({
          type: 'public',
          algorithm: { hash: { name: 'SHA-256' } },
          extractable: true,
          usages: ['verify'],
          handle: ECDSA_K256_PublicPem
        })

        let alg = new ECDSA({ name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } })

        let caller = () => {
          alg.exportKey('WRONG', key)
        }

        expect(caller).to.throw(NotSupportedError)
        expect(caller).to.throw('is not a supported key format')
      })
    })
  })

})//ECDSA TESTS