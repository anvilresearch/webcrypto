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
  RsaPrivateCryptoKey,
  RsaPublicKey,
  RsaPublicJwk,
  RsaPublicCryptoKey
} = require('../RsaKeyPairForTesting')

const {TextEncoder} = require('text-encoding')
const crypto = require('../../src')
const CryptoKey = require('../../src/keys/CryptoKey')
const CryptoKeyPair = require('../../src/keys/CryptoKeyPair')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const RsaKeyAlgorithm = require('../../src/dictionaries/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../../src/dictionaries/RsaHashedKeyAlgorithm')
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
    let alg, rsa, data, signature

    before(() => {
      alg = { name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' } }
      rsa = new RsaHashedKeyAlgorithm(alg)

      data = new TextEncoder().encode('signed with Chrome webcrypto')

      signature = new Uint8Array([
        84, 181, 186, 121, 235, 76, 199, 102, 174, 125, 176, 216, 94, 190,
        243, 201, 219, 114, 227, 61, 54, 194, 237, 14, 248, 204, 120, 109,
        249, 220, 229, 80, 44, 48, 86, 133, 96, 129, 85, 213, 70, 19, 126,
        0, 160, 91, 18, 185, 200, 102, 180, 181, 69, 27, 162, 181, 189, 110,
        188, 112, 124, 93, 57, 208, 91, 142, 182, 192, 87, 167, 193, 111,
        88, 5, 244, 108, 200, 150, 133, 68, 144, 208, 27, 155, 222, 213, 189,
        224, 156, 226, 124, 65, 178, 69, 71, 63, 243, 141, 3, 126, 209, 237,
        45, 179, 240, 255, 194, 245, 43, 148, 123, 97, 172, 239, 168, 221,
        44, 186, 72, 194, 29, 9, 171, 103, 125, 182, 39, 95, 163, 80, 3, 208,
        184, 184, 48, 114, 135, 7, 111, 114, 38, 25, 28, 234, 82, 18, 49, 113,
        20, 251, 59, 147, 206, 7, 134, 15, 189, 201, 253, 241, 120, 236, 58,
        235, 148, 27, 204, 233, 165, 31, 27, 223, 28, 10, 214, 159, 109, 186,
        239, 71, 126, 18, 63, 111, 198, 115, 226, 237, 145, 26, 12, 120, 56,
        166, 13, 195, 65, 11, 114, 149, 145, 255, 242, 97, 190, 255, 202, 219,
        144, 83, 238, 240, 182, 82, 165, 229, 118, 146, 29, 95, 127, 76, 188,
        247, 138, 254, 72, 18, 251, 42, 118, 156, 229, 66, 8, 106, 55, 106,
        83, 232, 234, 23, 195, 160, 167, 133, 14, 181, 126, 5, 36, 157, 2, 81,
        144, 83
      ])
    })

    it('should throw with non-private key', () => {
      expect(() => {
        rsa.sign(RsaPublicCryptoKey, new Uint8Array())
      }).to.throw('Signing requires a private key')
    })

    it('should return an ArrayBuffer', () => {
      rsa.sign(RsaPrivateCryptoKey, data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a RSASSA-PKCS1-v1_5 signature', () => {
      Buffer.from(rsa.sign(RsaPrivateCryptoKey, data))
        .should.eql(Buffer.from(signature.buffer))
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    let alg, rsa, data, signature

    before(() => {
      alg = { name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' } }
      rsa = new RsaHashedKeyAlgorithm(alg)

      data = new TextEncoder().encode('signed with Chrome webcrypto')

      signature = new Uint8Array([
        84, 181, 186, 121, 235, 76, 199, 102, 174, 125, 176, 216, 94, 190,
        243, 201, 219, 114, 227, 61, 54, 194, 237, 14, 248, 204, 120, 109,
        249, 220, 229, 80, 44, 48, 86, 133, 96, 129, 85, 213, 70, 19, 126,
        0, 160, 91, 18, 185, 200, 102, 180, 181, 69, 27, 162, 181, 189, 110,
        188, 112, 124, 93, 57, 208, 91, 142, 182, 192, 87, 167, 193, 111,
        88, 5, 244, 108, 200, 150, 133, 68, 144, 208, 27, 155, 222, 213, 189,
        224, 156, 226, 124, 65, 178, 69, 71, 63, 243, 141, 3, 126, 209, 237,
        45, 179, 240, 255, 194, 245, 43, 148, 123, 97, 172, 239, 168, 221,
        44, 186, 72, 194, 29, 9, 171, 103, 125, 182, 39, 95, 163, 80, 3, 208,
        184, 184, 48, 114, 135, 7, 111, 114, 38, 25, 28, 234, 82, 18, 49, 113,
        20, 251, 59, 147, 206, 7, 134, 15, 189, 201, 253, 241, 120, 236, 58,
        235, 148, 27, 204, 233, 165, 31, 27, 223, 28, 10, 214, 159, 109, 186,
        239, 71, 126, 18, 63, 111, 198, 115, 226, 237, 145, 26, 12, 120, 56,
        166, 13, 195, 65, 11, 114, 149, 145, 255, 242, 97, 190, 255, 202, 219,
        144, 83, 238, 240, 182, 82, 165, 229, 118, 146, 29, 95, 127, 76, 188,
        247, 138, 254, 72, 18, 251, 42, 118, 156, 229, 66, 8, 106, 55, 106,
        83, 232, 234, 23, 195, 160, 167, 133, 14, 181, 126, 5, 36, 157, 2, 81,
        144, 83
      ])
    })

    it('should throw with non-private key', () => {
      expect(() => {
        rsa.verify(RsaPrivateCryptoKey, new Uint8Array())
      }).to.throw('Verifying requires a public key')
    })

    it('should return true with valid signature', () => {
      rsa.verify(RsaPublicCryptoKey, signature, data).should.equal(true)
    })

    it('should return false with invalid signature', () => {
      let invalidData = new TextEncoder().encode('invalid signature')
      rsa.verify(RsaPublicCryptoKey, signature, invalidData).should.equal(false)
    })
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    let alg, rsa, cryptoKeyPair

    before(() => {
      alg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }
      rsa = new RsaHashedKeyAlgorithm(alg)
      return Promise.resolve()
        .then(() => cryptoKeyPair = rsa.generateKey(alg, true, ['sign', 'verify']))

    })

    it('should throw with invalid usages', () => {
      expect(() => {
        rsa.generateKey(alg, true, ['sign', 'verify', 'wrong'])
      }).to.throw('Key usages can only include "sign" and "verify"')
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
        .should.be.instanceof(RsaHashedKeyAlgorithm)
    })

    it('should set private key algorithm', () => {
      cryptoKeyPair.privateKey.algorithm
        .should.be.instanceof(RsaHashedKeyAlgorithm)
    })

    it('should set public key algorithm name', () => {
      cryptoKeyPair.publicKey.algorithm.name
        .should.equal('RSASSA-PKCS1-v1_5')
    })

    it('should set private key algorithm name', () => {
      cryptoKeyPair.privateKey.algorithm.name
        .should.equal('RSASSA-PKCS1-v1_5')
    })

    //it('should set public key algorithm hash', () => {
    //  cryptoKeyPair.publicKey.algorithm.hash
    //    .should.be.instanceof(KeyAlgorithm)
    //})

    //it('should set private key algorithm hash', () => {
    //  cryptoKeyPair.privateKey.algorithm.hash
    //    .should.be.instanceof(KeyAlgorithm)
    //})

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
        .should.include('-----BEGIN RSA PRIVATE KEY-----')
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
