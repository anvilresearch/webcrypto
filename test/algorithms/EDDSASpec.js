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
const JsonWebKey = require('../../src/keys/JsonWebKey')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const EcKeyAlgorithm = require('../../src/dictionaries/EcKeyAlgorithm')
const EDDSA = require('../../src/algorithms/EDDSA')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')
const CurrentlyNotSupportedError = require('../../src/errors/CurrentlyNotSupportedError')

/**
 * Code under test
 */
// Taken from https://tools.ietf.org/html/rfc8032#section-7.1, Test 2
let edd25519_private = { 
  type: 'private',
  hex: `4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb`
}
let edd25519_public = {
  type: 'public',
  hex: `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c` 
}

/**
 * Tests
 */
  describe(`EDDSA`, () => {
    /**
     * dictionaries getter
     */
    describe.skip('dictionaries getter', () => {
      it('should return an array', () => {
        eddsa.dictionaries.should.eql([
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
          eddsa.members.hash.should.equal('HashAlgorithmIdentifier')
      })
    })

    /**
     * sign
     */
    describe('sign', () => {
      let alg, eddsa, data, signature, eddsaPublicKey, eddsaPrivateKey

      before(() => {
          alg = { name: 'EDDSA', namedCurve: 'Ed25519' }
          eddsa = new EDDSA(alg) 
          eddsaPublicKey = eddsa.importKey(
              "hex",
              edd25519_public,
              alg,
              true,
              ['verify']
            )
          eddsaPrivateKey = eddsa.importKey(
              "hex",
              edd25519_private,
              alg,
              true,
              ['sign']
            )
          data = Buffer.from('72','hex')
          signature = Buffer.from(`92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00`,'hex')
      })

      it('should throw with non-private key', () => {
        expect(() => {
          eddsa.sign(eddsaPublicKey, new Uint8Array())
        }).to.throw('Signing requires a private key')
      })

      it('should return an ArrayBuffer', () => {
        eddsa.sign(eddsaPrivateKey, data).should.be.instanceof(ArrayBuffer)
      })

      it('should return an EDDSA signature', () => {
        Buffer.from(eddsa.sign(eddsaPrivateKey, data))
          .should.deep.equal(signature)
      })

      it('should throw with invalid data type', () => {
        expect(() => {
          eddsa.sign(eddsaPrivateKey, {})
        }).to.throw('Data must be an Array, Buffer or hex string')
      })
    })

    /**
     * verify
     */
    describe('verify', () => {
      let alg, eddsa, data, signature, eddsaPublicKey, eddsaPrivateKey

      before(() => {
          alg = { name: 'EDDSA', namedCurve: 'Ed25519' }
          eddsa = new EDDSA(alg)
          eddsaPublicKey = eddsa.importKey(
              "hex",
              edd25519_public,
              alg,
              true,
              ['verify']
            )
          eddsaPrivateKey = eddsa.importKey(
              "hex",
              edd25519_private,
              alg,
              true,
              ['sign']
            )
          data = Buffer.from('72','hex')
          signature = Buffer.from(`92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00`,'hex')
          signature = Uint8Array.from(signature).buffer
      })

      it('should throw with non-private key', () => {
        expect(() => {
          eddsa.verify(eddsaPrivateKey, '','')
        }).to.throw('Verifying requires a public key')
      })

      it('should return true with valid signature', () => {
        eddsa.verify(eddsaPublicKey, signature, data).should.equal(true)
      })

      it('should return false with invalid signature', () => {
        let invalidData = Buffer.from(new TextEncoder().encode('invalid signature'))
        eddsa.verify(eddsaPublicKey, signature, invalidData).should.equal(false)
      })
    })

    /**
     * generateKey
     */
    describe('generateKey', () => {
      let alg, eddsa, cryptoKeyPair

      before(() => {
        alg = { name: 'EDDSA', namedCurve: 'Ed25519' }
        eddsa = new EDDSA(alg)
        return Promise.resolve()
          .then(() => cryptoKeyPair = eddsa.generateKey(alg, true, ['sign', 'verify']))

      })

      it('should throw with invalid usages', () => {
        expect(() => {
          eddsa.generateKey(alg, true, ['sign', 'verify', 'wrong'])
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
          .should.be.instanceof(EDDSA)
      })

      it('should set private key algorithm', () => {
        cryptoKeyPair.privateKey.algorithm
          .should.be.instanceof(EDDSA)
      })

      it('should set public key algorithm name', () => {
        cryptoKeyPair.publicKey.algorithm.name
          .should.equal('EDDSA')
      })

      it('should set private key algorithm name', () => {
        cryptoKeyPair.privateKey.algorithm.name
          .should.equal('EDDSA')
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
              kty:  "OKP",
              crv:  "Ed25519",
              d:    "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
              x:    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
            alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
            ec = new EDDSA(alg)
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
              kty:  "OKP",
              crv:  "Ed25519",
              x:    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
            alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
            ec = new EDDSA(alg)
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
            alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
            ec = new EDDSA(alg)
            key = {
              kty:  "WRONG",
              crv:  "Ed25519",
              x:    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }

          })

          it('should throw DataError', () => {
            expect(() => {
              ec.importKey('jwk', key, alg, false, ['verify'])
            }).to.throw('Key type must be "OKP"')
          })
        })

        describe('invalid key use', () => {
          let key, alg, eddsa

          before(() => {            
            key = {
              kty:  "OKP",
              crv:  "Ed25519",
              d:    "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
              x:    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
            alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
            eddsa = new EDDSA(alg)

          })

          it('should throw DataError', () => {
            expect(() => {
              eddsa.importKey('jwk', key, alg, false, ['verify'])
            }).to.throw('Key usages must include "sign"')
          })
        })

        describe(`private Ed25519 key`, () => {
          let alg,eddsa,key,eddsaPrivateKey

          before(() => {
          alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
          eddsa = new EDDSA(alg)
          eddsaPrivateKey = eddsa.importKey(
            "jwk",
            {
              kty:  "OKP",
              crv:  "Ed25519",
              d:    "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
              x:    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            },
            alg,
            true,
            ['sign']
          )
            key = eddsaPrivateKey
          })

          it('should define type', () => {
            key.type.should.equal('private')
          })

          it('should define algorithm', () => {
            key.algorithm.should.be.instanceof(EDDSA)
          })

          it('should define extractable', () => {
            key.extractable.should.equal(true)
          })

          it('should define usages', () => {
            key.usages.should.eql(['sign'])
          })
        })

        describe(`public Ed25519 key`, () => {
          let alg,eddsa,key, eddsaPublicKey

          before(() => {
          alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
          eddsa = new EDDSA(alg)
          eddsaPublicKey = eddsa.importKey(
              "jwk", 
              {
                kty:  "OKP",
                crv:  "Ed25519",
                x:    "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
              },
              alg,
              true,
              ['verify']
            )
            key = eddsaPublicKey
          })

          it('should define type', () => {
            key.type.should.equal('public')
          })

          it('should define algorithm', () => {
            key.algorithm.should.be.instanceof(EDDSA)
          })

          it('should define extractable', () => {
            key.extractable.should.equal(true)
          })

          it('should define usages', () => {
            key.usages.should.eql(['verify'])
          })
        })

    describe('with "raw" format', () => {})
    })
    
    describe('with "hex" format', () => {
      describe('private key and invalid usages', () => {
            let key, alg, ec

            before(() => {
              key = edd25519_private
              alg = {
                  name: 'EDDSA', namedCurve: 'Ed25519',
              }
              ec = new EDDSA(alg)
            })

            it('should throw SyntaxError', () => {
              expect(() => {
                ec.importKey('hex', key, alg , false, ['bad'])
              }).to.throw('Key usages must include "sign"')
            })
          })

          describe('non-private key and invalid usages', () => {
            let key, alg, ec

            before(() => {
              key = edd25519_public
              alg = {
                  name: 'EDDSA', namedCurve: 'Ed25519',
              }
              ec = new EDDSA(alg)
            })

            it('should throw SyntaxError', () => {
              expect(() => {
                ec.importKey('hex', key, alg, false, ['bad'])
              }).to.throw('Key usages must include "verify"')
            })
          })

          describe('invalid key type', () => {
            let key, alg, ec

            before(() => {
              alg = {
                  name: 'EDDSA', namedCurve: 'Ed25519',
              }
              ec = new EDDSA(alg)
              key = { 
                type: "GARBAGE",
                hex: edd25519_public.hex
              }
            })

            it('should throw DataError', () => {
              expect(() => {
                ec.importKey('hex', key, alg, false, ['verify'])
              }).to.throw('Key type can only be "private" or "public".')
            })
          })

          describe('invalid key use', () => {
            let key, alg, eddsa

            before(() => {            
              key = edd25519_private
              alg = {
                  name: 'EDDSA', namedCurve: 'Ed25519',
              }
              eddsa = new EDDSA(alg)
            })

            it('should throw DataError', () => {
              expect(() => {
                eddsa.importKey('hex', key, alg, false, ['verify'])
              }).to.throw('Key usages must include "sign"')
            })
          })

          describe(`private Ed25519 key`, () => {
            let alg,eddsa,key,eddsaPrivateKey

            before(() => {
              alg = {
                  name: 'EDDSA', namedCurve: 'Ed25519',
              }
              eddsa = new EDDSA(alg)
              eddsaPrivateKey = eddsa.importKey(
                "hex",
                edd25519_private,
                alg,
                true,
                ['sign']
              )
              key = eddsaPrivateKey
            })

            it('should define type', () => {
              key.type.should.equal('private')
            })

            it('should define algorithm', () => {
              key.algorithm.should.be.instanceof(EDDSA)
            })

            it('should define extractable', () => {
              key.extractable.should.equal(true)
            })

            it('should define usages', () => {
              key.usages.should.eql(['sign'])
            })
          })

          describe(`public Ed25519 key`, () => {
            let alg,eddsa,key, eddsaPublicKey

            before(() => {
            alg = {
                  name: 'EDDSA', namedCurve: 'Ed25519',
              }
            eddsa = new EDDSA(alg)
            eddsaPublicKey = eddsa.importKey(
                "hex",
                edd25519_public,
                alg,
                true,
                ['verify']
              )
              key = eddsaPublicKey
            })

            it('should define type', () => {
              key.type.should.equal('public')
            })

            it('should define algorithm', () => {
              key.algorithm.should.be.instanceof(EDDSA)
            })

            it('should define extractable', () => {
              key.extractable.should.equal(true)
            })

            it('should define usages', () => {
              key.usages.should.eql(['verify'])
            })
          })
        })

      describe('with other format', () => {
        it('should throw NotSupportedError', () => {
          let alg = new EDDSA({ name: 'EDDSA', namedCurve: 'Ed25519' })

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
            let ec = new EDDSA({ name: 'EDDSA', namedCurve: 'Ed25519' })
            ec.exportKey('format', {})
          }).to.throw('Missing key material')
        })
      })

      describe('with "spki" format', () => {})
      describe('with "pkcs8 format"', () => {})

      describe('with "jwk" format', () => {
        let alg,eddsa,key, eddsaPublicKey

          before(() => {
          alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
          eddsa = new EDDSA(alg)
          eddsaPublicKey = eddsa.importKey(
              "hex",
              edd25519_public,
              alg,
              true,
              ['verify']
            )
            key = eddsaPublicKey
          })

          it('should return a valid key', () => {
            eddsa.exportKey("jwk",key).should.be.instanceof(JsonWebKey)
          })

      })
      describe('with "raw" format', () => {
        let alg,eddsa,key, eddsaPublicKey

          before(() => {
          alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
          eddsa = new EDDSA(alg)
          eddsaPublicKey = eddsa.importKey(
              "hex",
              edd25519_public,
              alg,
              true,
              ['verify']
            )
            key = eddsaPublicKey
          })

          it('should return a valid key', () => {
            eddsa.exportKey("raw",key).should.be.instanceof(Buffer)
          })
      })
      describe('with "hex" format', () => {
        let alg,eddsa,key, eddsaPublicKey

          before(() => {
          alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
          eddsa = new EDDSA(alg)
          eddsaPublicKey = eddsa.importKey(
              "hex",
              edd25519_public,
              alg,
              true,
              ['verify']
            )
            key = eddsaPublicKey
          })

          it('should return a valid key', () => {
            eddsa.exportKey("hex",key).should.be.an('string')
          })
      })
      describe('with other format', () => {
        let alg,eddsa,key, eddsaPublicKey
        before(() => {
          alg = {
                name: 'EDDSA', namedCurve: 'Ed25519',
            }
          eddsa = new EDDSA(alg)
          eddsaPublicKey = eddsa.importKey(
              "hex",
              edd25519_public,
              alg,
              true,
              ['verify']
            )
            key = eddsaPublicKey
          })

        it('should throw NotSupportedError', () => {          
          let caller = () => {
            eddsa.exportKey('WRONG', key)
          }
          expect(caller).to.throw(NotSupportedError)
          expect(caller).to.throw('is not a supported key format')
        })
      })
    })
  })//EDDSA TESTS