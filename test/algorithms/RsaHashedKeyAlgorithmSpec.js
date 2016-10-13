/**
 * Test dependencies
 */
const chai = require('chai')
const expect = chai.expect

/**
 * Assertions
 */
chai.should()

/**
 * Code under test
 */
const {
  RsaPrivateKey,
  RsaPrivateJwk,
  RsaPublicKey,
  RsaPublicJwk
} = require('../RsaKeyPairForTesting')

const CryptoKey = require('../../src/CryptoKey')
const CryptoKeyPair = require('../../src/CryptoKeyPair')
const KeyAlgorithm = require('../../src/algorithms/KeyAlgorithm')
const RsaKeyAlgorithm = require('../../src/algorithms/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../../src/algorithms/RsaHashedKeyAlgorithm')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')

/**
 * Tests
 */
describe('RsaHashedKeyAlgorithm', () => {

  /**
   * class
   */
  describe('class', () => {
    it('should inherit from RsaKeyAlgorithm', () => {
      let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
      alg.should.be.instanceof(RsaKeyAlgorithm)
    })
  })

  /**
   * dictionaries getter
   */
  describe('dictionaries getter', () => {
    it('should return an array', () => {
      RsaHashedKeyAlgorithm.dictionaries.should.eql([
        KeyAlgorithm,
        RsaKeyAlgorithm,
        RsaHashedKeyAlgorithm
      ])
    })
  })

  /**
   * members getter
   */
  describe('members getter', () => {
    it('should return an object', () => {
      RsaHashedKeyAlgorithm.members.publicExponent.should.equal('BufferSource')
      RsaHashedKeyAlgorithm.members.hash.should.equal('HashAlgorithmIdentifier')
    })
  })

  /**
   * sign
   */
  describe('sign', () => {
    describe('with non-private key', () => {
      it('should throw InvalidAccessError', () => {
        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
        let key = new CryptoKey({
          type: 'public',
          algorithm: alg,
          extractable: false,
          usages: ['verify']
        })

        expect(() => {
          alg.sign(key, new ArrayBuffer())
        }).to.throw('Signing requires a private key')
      })
    })

    describe('with invalid arguments', () => {
      it('should throw OperationError', () => {
        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
        let key = new CryptoKey({
          type: 'private',
          algorithm: alg,
          extractable: false,
          usages: ['verify']
        })

        expect(() => {
          alg.sign(key, new ArrayBuffer())
        }).to.throw(OperationError)
      })
    })

    describe('with valid arguments', () => {
      it('should return ArrayBuffer', () => {
        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
        let key = new CryptoKey({
          type: 'private',
          algorithm: alg,
          extractable: false,
          usages: ['sign'],
          handle: RsaPrivateKey
        })

        alg.sign(key, new ArrayBuffer()).should.be.instanceof(Uint8Array)
      })

      it('should sign with the correct hash')
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    describe('with non-public key', () => {
      it('should throw InvalidAccessError', () => {
        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
        let key = new CryptoKey({
          type: 'private',
          algorithm: alg,
          extractable: false,
          usages: ['verify']
        })

        expect(() => {
          alg.verify(key, new ArrayBuffer, new ArrayBuffer())
        }).to.throw('Verifying requires a public key')
      })
    })

    describe('with invalid arguments', () => {
      it('should throw OperationError', () => {
        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
        let key = new CryptoKey({
          type: 'public',
          algorithm: alg,
          extractable: false,
          usages: ['verify']
        })

        expect(() => {
          alg.verify(key, new ArrayBuffer(), new ArrayBuffer())
        }).to.throw(OperationError)
      })
    })

    describe('with valid arguments', () => {
      it('should return ArrayBuffer', () => {
        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
        let key = new CryptoKey({
          type: 'public',
          algorithm: alg,
          extractable: false,
          usages: ['verify'],
          handle: RsaPublicKey
        })

        alg.verify(key, new ArrayBuffer, new ArrayBuffer()).should.equal(false)
      })

      it('should verify with the correct hash')
    })
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    describe('with invalid usages', () => {
    })

    describe('with invalid params', () => {
    })

    describe('with valid arguments', () => {
      let alg, keypair, publicKey, privateKey, error

      before(() => {
        alg = new RsaHashedKeyAlgorithm({
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 1024,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: 'SHA-256' }
        })

        keypair = error = alg.generateKey(alg, false, ['sign', 'verify'])
        publicKey = keypair.publicKey
        privateKey = keypair.privateKey
      })

      it('should return a CryptoKeyPair', () => {
        keypair.should.be.instanceof(CryptoKeyPair)
      })

      it('should return a CryptoKey publicKey', () => {
        publicKey.should.be.instanceof(CryptoKey)
      })

      it('should define publicKey type', () => {
        publicKey.type.should.equal('public')
      })

      it('should define publicKey algorithm', () => {
        publicKey.algorithm.should.eql(alg)
      })

      it('should define publicKey to be extractable', () => {
        publicKey.extractable.should.equal(true)
      })

      it('should define publicKey usages', () => {
        publicKey.usages.should.eql(['verify'])
      })

      it('should define publicKey handle', () => {
        publicKey.handle.should.be.a.string
      })

      it('should return a CryptoKey privateKey', () => {
        privateKey.should.be.instanceof(CryptoKey)
      })

      it('should define privateKey type', () => {
        privateKey.type.should.equal('private')
      })

      it('should define privateKey algorithm', () => {
        privateKey.algorithm.should.eql(alg)
      })

      it('should define privateKey extractable', () => {
        privateKey.extractable.should.equal(false)
      })

      it('should define privateKey usages', () => {
        privateKey.usages.should.eql(['sign'])
      })

      it('should define privateKey handle', () => {
        publicKey.handle.should.be.a.string
      })
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
        let key, alg

        before(() => {
          key = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            d: "FAKE",
            alg: "RS256",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['bad'])
          }).to.throw('Key usages must include "sign"')
        })
      })

      describe('non-private key and invalid usages', () => {
        let key, alg

        before(() => {
          key = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['bad'])
          }).to.throw('Key usages must include "verify"')
        })
      })

      describe('invalid key type', () => {
        let key, alg

        before(() => {
          key = {
            kty: "WRONG",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['verify'])
          }).to.throw('Key type must be RSA')
        })
      })

      describe('invalid key use', () => {
        let key, alg

        before(() => {
          key = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            use: "WRONG",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['verify'])
          }).to.throw('Key use must be "sig"')
        })
      })

      describe('RS1 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS1",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-1 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-1')
        })
      })

      describe('RS256 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS256",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-256 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-256')
        })
      })

      describe('RS384 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS384",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-384 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-384')
        })
      })

      describe('RS512 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RS512",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should set SHA-512 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-512')
        })
      })

      describe('invalid key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "WTF",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', jwk, alg, false, ['verify'])
          }).to.throw('Key alg must be "RS1", "RS256", "RS384", or "RS512"')
        })
      })

      describe.skip('undefined key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            ext: true
          }

          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', jwk, alg, false, ['verify'])
        })

        it('should not define hash', () => {
          expect(key.algorithm.hash).to.be.undefined
        })
      })

      describe('private RSA key', () => {
        let key, alg

        before(() => {
          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', RsaPrivateJwk, alg, false, ['sign'])
        })

        it('should define type', () => {
          key.type.should.equal('private')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RsaHashedKeyAlgorithm)
        })

        it('should define extractable', () => {
          key.extractable.should.equal(false)
        })

        it('should define usages', () => {
          key.usages.should.eql(['sign'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN RSA PRIVATE KEY-----')
        })
      })

      describe('public RSA key', () => {
        let key, alg

        before(() => {
          alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          key = alg.importKey('jwk', RsaPublicJwk, alg, false, ['verify'])
        })

        it('should define type', () => {
          key.type.should.equal('public')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RsaHashedKeyAlgorithm)
        })

        it('should define extractable', () => {
          key.extractable.should.equal(true)
        })

        it('should define usages', () => {
          key.usages.should.eql(['verify'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN RSA PUBLIC KEY-----')
        })
      })
    })

    describe('with other format', () => {
      it('should throw NotSupportedError', () => {
        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })

        let caller = () => {
          alg.importKey('WRONG', RsaPublicJwk, alg, false, ['verify'])
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
          let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          alg.exportKey('format', {})
        }).to.throw('Missing key material')
      })
    })

    describe('with "spki" format', () => {})
    describe('with "pkcs8 format"', () => {})

    describe('with "jwk" format', () => {
      describe('SHA-1 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-1' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS1"', () => {
          jwk.alg.should.equal('RS1')
        })
      })

      describe('SHA-256 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-256' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS256"', () => {
          jwk.alg.should.equal('RS256')
        })
      })

      describe('SHA-384 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-384' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS384"', () => {
          jwk.alg.should.equal('RS384')
        })
      })

      describe('SHA-512 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-512' } },
            extractable: true,
            usages: ['verify'],
            handle: RsaPublicKey
          })

          let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RS512"', () => {
          jwk.alg.should.equal('RS512')
        })
      })

      describe('other hash', () => {})
    })

    describe('with other format', () => {
      it('should throw NotSupportedError', () => {
        let key = new CryptoKey({
          type: 'public',
          algorithm: {},
          extractable: true,
          usages: ['verify'],
          handle: RsaPublicKey

        })

        let alg = new RsaHashedKeyAlgorithm({ name: 'RSASSA-PKCS1-v1_5' })

        let caller = () => {
          alg.exportKey('WRONG', key)
        }

        expect(caller).to.throw(NotSupportedError)
        expect(caller).to.throw('is not a supported key format')
      })
    })
  })
})
