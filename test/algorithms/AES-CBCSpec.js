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
const AesKeyAlgorithm = require('../../src/dictionaries/AesKeyAlgorithm')
const AES_CBC = require('../../src/algorithms/AES-CBC')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')

/**
 * Test code
 */
const good_iv =  Buffer.from([ 220, 29, 37, 164, 41, 84, 153, 197, 157, 122, 156, 254, 196, 161, 114, 74 ])
const bad_iv = Buffer.from([ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 ]) // too short

/**
 * Tests
 */
describe('AES_CBC', () => {
  /**
   * dictionaries getter
   */
  describe.skip('dictionaries getter', () => {
    it('should return an array', () => {
      AES_CBC.dictionaries.should.eql([
        KeyAlgorithm,
        AesKeyAlgorithm
      ])
    })
  })

  /**
   * members getter
   */
  describe.skip('members getter', () => {
    it('should return an object', () => {
      AES_CBC.members.publicExponent.should.equal('BufferSource')
    })
  })

  /**
   * encrypt
   */
  describe('encrypt', () => {
    let aes, key, data, signature

    before(() => {
        aes = new AES_CBC({ name: "AES-CBC", length: 256 })
        key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true,
            },
            {
                name: "AES-CBC",
            },
            true,
            ["encrypt", "decrypt"]
        )
        data = new TextEncoder().encode('signed with Chrome Webcrypto')
        signature = new Uint8Array([
            76, 82, 211, 155, 13, 154, 24, 6, 156, 203, 50,
            171, 210, 17, 88, 145, 32, 225, 125, 119, 179,
            197, 224, 210, 122, 43, 255, 159, 59, 195, 206, 210])
    })

    it("should throw with invalid iv length", () => {
        expect(() => {
            aes.encrypt({name: "AES-CBC", iv: bad_iv},key,new Uint8Array())
        }).to.throw('IV Length must be exactly 16 bytes')
    })

    it('should return an ArrayBuffer', () => {
      aes.encrypt({name: "AES-CBC", iv: good_iv},key,data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a valid encryption', () => {
        Buffer.from(aes.encrypt({name: "AES-CBC", iv: good_iv},key,data))
        .should.eql(Buffer.from(signature.buffer))
    })
  }) // encrypt

/**
 * decrypt
 */
  describe('decrypt', () => {
    let aes, key, data, signature
    before(() => {
        aes = new AES_CBC({ name: "AES-CBC", length: 256 })
        key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true,
            },
            {
                name: "AES-CBC",
            },
            true,
            ["encrypt", "decrypt"]
        )
        data = new Uint8Array([
            76, 82, 211, 155, 13, 154, 24, 6, 156,
            203, 50, 171, 210, 17, 88, 145, 32, 225,
            125, 119, 179, 197, 224, 210, 122, 43,
            255, 159, 59, 195, 206, 210])
        signature = new TextEncoder().encode('signed with Chrome Webcrypto')
    })

    it("should throw with invalid iv length", () => {
        expect(() => {
            aes.decrypt({name: "AES-CBC", iv: bad_iv},key,new Uint8Array())
        }).to.throw('IV Length must be exactly 16 bytes')
    })

    it('should return an ArrayBuffer', () => {
      aes.decrypt({name: "AES-CBC", iv: good_iv},key,data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a valid encryption', () => {
        Buffer.from(aes.decrypt({name: "AES-CBC", iv: good_iv},key,data))
        .should.eql(Buffer.from(signature.buffer))
    })
  }) // decrypt

/**
 * generateKey
 */
  describe('generateKey', () => {
    let alg, aes, cryptoKey

    before(() => {
        alg = {
            name: "AES-CBC",
            length: 256,
        }
        aes = new AES_CBC(alg)
        return Promise.resolve()
        .then(() => cryptoKey = aes.generateKey(alg,true,["encrypt", "decrypt"]))
    })

    it('should throw with invalid usages', () => {
      expect(() => {
         aes.generateKey(alg, true, ['encrypt', 'decrypt', 'wrong'])
        }).to.throw('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
    })

    it('should throw with invalid paramater length', () => {
      expect(() => {
         aes.generateKey({name:"AES-CBC",length:100}, true, ['encrypt', 'decrypt'])
        }).to.throw('Member length must be 128, 192, or 256.')
    })

    it('should return CryptoKey', () => {
      cryptoKey.should.be.instanceof(CryptoKey)
    })

    it('should be a secret key type', () => {
      cryptoKey.type.should.equal('secret')
    })

    it('should have AES_CBC type for algorithm', () => {
      cryptoKey.algorithm.should.instanceof(AES_CBC)
    })

    it('should set algorithm name', () => {
       cryptoKey.algorithm.name
        .should.equal('AES-CBC')
    })

   it('should set key as extractable', () => {
      cryptoKey.extractable.should.equal(true)
    })

    it('should set key usages', () => {
      cryptoKey.usages.should.eql(['encrypt','decrypt'])
    })

    it('should have correct length key handle', () => {
      cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length/8)
    })

    it('should generate a random handle each time', () => {
      cryptoKey.handle.should.not.equal(
          aes.generateKey(alg, true, ['encrypt', 'decrypt']).handle
      )
    })
  })//generateKey

/**
 * importKey
 */
  describe('importKey', () => {
    let aes
        before(() => {
            aes = new AES_CBC({ name: "AES-CBC", length: 256 })
        })

    it('should expect only "raw" or "jwk" formats', () => {
          expect(() => {
            aes.importKey('WRONG',{},{},true,[])
          }).to.throw('WRONG is not a supported key format')
        })

    describe('with "raw" format', () => {
        let alg, aes, raw, cryptoKey
        before(() => {
            alg = {
                name: "AES-CBC",
                length: 256,
            }
            aes = new AES_CBC(alg)
            raw = new Uint8Array([99, 76, 237, 223, 177, 224, 59, 31, 129, 99, 180, 144, 141, 133, 102, 174, 168, 79, 144, 238, 56, 34, 45, 137, 113, 191, 114, 201, 213, 3, 61, 241])
            return Promise.resolve()
            .then(() => cryptoKey = aes.importKey("raw",raw,{name:"AES-CBC"},true,["encrypt", "decrypt"]) )
        })

        it('should expect a suitable raw length', () => {
          expect(() => {
            aes.importKey('raw', new Uint8Array([1,2,3,4]), {name:"AES-CBC"} , true, ['encrypt','decrypt'])
          }).to.throw('Length of data bits must be 128, 192 or 256.')
        })

        it('should be a secret key type', () => {
            cryptoKey.type.should.equal('secret')
        })

        it('should have AES_CBC type for algorithm', () => {
            cryptoKey.algorithm.should.instanceof(AES_CBC)
        })

        it('should set algorithm name', () => {
            cryptoKey.algorithm.name
            .should.equal('AES-CBC')
        })

        it('should set key as extractable', () => {
            cryptoKey.extractable.should.equal(true)
        })

        it('should set key usages', () => {
            cryptoKey.usages.should.eql(['encrypt','decrypt'])
        })

        it('should have correct length key handle', () => {
            cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length/8)
        })
    })//raw

    describe('with "jwk" format', () => {
        let alg, aes, key, cryptoKey
        before(() => {
            alg = {
                name: "AES-CBC",
                length: 256,
            }
            aes = new AES_CBC(alg)
            key = {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true,
            }
            return Promise.resolve()
            .then(() => cryptoKey = aes.importKey("jwk",key,{name:"AES-CBC"},true,["encrypt", "decrypt"]))
        })

        it('should expect a suitable jwk format', () => {
          expect(() => {
            aes.importKey('jwk', "Incorrect", {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('Invalid jwk format')
        })

        it('should expect correct kty format', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "WRONG",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true,
            }, {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('kty property must be "oct"')
        })

        it('should expect data in k property', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "oct",
                alg: "A256CBC",
                ext: true,
            }, {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('k property must not be empty')
        })

        it('should expect A128CBC when data length is 16', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13Yw",
                alg: "A256CBC",
                ext: true,
            }, {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('Algorithm "A128CBC" must be 128 bits in length')
        })

        it('should expect A192CBC when data length is 24', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13YwY7SQjYVmrq",
                alg: "A256CBC",
                ext: true,
            }, {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('Algorithm "A192CBC" must be 192 bits in length')
        })

        it('should expect A256CBC when data length is 32', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A192CBC",
                ext: true,
            }, {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('Algorithm "A256CBC" must be 256 bits in length')
        })

        it('should expect mismatched length when k is not appropriate base64url', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "oct",
                k: "Y0zt37",
                alg: "A256CBC",
                ext: true,
            }, {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('Algorithm and data length mismatch')
        })

        it('should expect correct value when "use" field is used', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                use: "WRONG",
                ext: true,
            }, {name:"AES-CBC"} , false, ['encrypt','decrypt'])
          }).to.throw('Key use must be "enc"')
        })

        it('should expect valid key operations', () => {
          expect(() => {
            aes.importKey('jwk',key, {name:"AES-CBC"} , false, ['encrypt','decrypt','WRONG'])
          }).to.throw('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
        })

        it('should expect non extractable to not be extractable', () => {
          expect(() => {
            aes.importKey('jwk',{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: false,
            }, {name:"AES-CBC"} , true, ['encrypt','decrypt'])
          }).to.throw('Cannot be extractable when "ext" is set to false')
        })

        it('should be a secret key type', () => {
            cryptoKey.type.should.equal('secret')
        })

        it('should have AES_CBC type for algorithm', () => {
            cryptoKey.algorithm.should.instanceof(AES_CBC)
        })

        it('should set algorithm name', () => {
            cryptoKey.algorithm.name
            .should.equal('AES-CBC')
        })

        it('should set key as extractable', () => {
            cryptoKey.extractable.should.equal(true)
        })

        it('should set key usages', () => {
            cryptoKey.usages.should.eql(['encrypt','decrypt'])
        })

        it('should have correct length key handle', () => {
            cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length/8)
        })
    })//jwk
  })//importKey

/**
 * exportKey
 */
  describe('exportKey', () => {
    let aes
    before(() => {
        aes = new AES_CBC({ name: "AES-CBC", length: 256 })
    })

    it('should have a valid handle in the key', () => {
        expect(() => {
        aes.exportKey('raw',{})
        }).to.throw('Missing key material')
    })

    it('should expect only "raw" or "jwk" formats', () => {
        expect(() => {
        aes.exportKey('WRONG',{handle:"Something"})
        }).to.throw('WRONG is not a supported key format')
    })

    describe('with "raw" format', () => {
        let alg, aes, key, raw
        before(() => {
            alg = {
                name: "AES-CBC",
                length: 256,
            }
            aes = new AES_CBC(alg)
            key = aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true
            },{name:"AES-CBC"},true,["encrypt", "decrypt"])
            raw = aes.exportKey("raw",key)
        })

        it('should return a valid object', () => {
            raw.should.instanceof(Object)
        })
    })//raw

    describe('with "jwk" format', () => {
        let alg, aes, key, jwk
        before(() => {
            alg = {
                name: "AES-CBC",
                length: 256,
            }
            aes = new AES_CBC(alg)
            key = aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true
            },{name:"AES-CBC"},true,["encrypt", "decrypt"])
            jwk = aes.exportKey("jwk",key)
        })

        it('should return a valid object', () => {
            jwk.should.instanceof(Object)
        })

        it('should expect correct kty field', () => {
            jwk.kty.should.eql("oct")
        })

        it('should expect A128CBC when data length is 16', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13Yw",
                alg: "A128CBC",
                ext: true
            },{name:"AES-CBC"},true,["encrypt", "decrypt"])).alg.should.eql("A128CBC")
        })

        it('should expect A192CBC when data length is 24', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13YwY7SQjYVmrq",
                alg: "A192CBC",
                ext: true
            },{name:"AES-CBC"},true,["encrypt", "decrypt"])).alg.should.eql("A192CBC")
        })

        it('should expect A256CBC when data length is 32', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CBC",
                ext: true
            },{name:"AES-CBC"},true,["encrypt", "decrypt"])).alg.should.eql("A256CBC")
        })
    })//jwk
  })//exportKey

})
