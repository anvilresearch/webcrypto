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
const AES_CTR = require('../../src/algorithms/AES-CTR')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')
const CurrentlyNotSupportedError = require('../../src/errors/CurrentlyNotSupportedError')

/**
 * Test code
 */
const good_iv =  Buffer.from([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 ])
const good_iv2 =  Buffer.from([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7 ])
const bad_iv = new Array()

/**
 * Tests
 */
describe('AES_CTR', () => {
  /**
   * dictionaries getter
   */
  describe.skip('dictionaries getter', () => {
    it('should return an array', () => {
      AES_CTR.dictionaries.should.eql([
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
      AES_CTR.members.publicExponent.should.equal('BufferSource')
    })
  })

  /**
   * encrypt
   */
  describe('encrypt', () => {
    let aes, key, data, signature

    before(() => {
        aes = new AES_CTR({ name: "AES-CTR", length: 256 })
        key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CTR",
                ext: true,
            },
            {
                name: "AES-CTR",
            },
            true,
            ["encrypt", "decrypt"]
        )
        data = new TextEncoder().encode('Encoded with WebCrypto')
        signature = new Uint8Array([
            105, 17, 182, 253, 106, 236, 160, 39, 22, 23, 4, 230, 
            196, 158, 208, 79, 149, 225, 178, 37, 160, 63])
    })

    it("should throw with empty counter", () => {
        expect(() => {
            aes.encrypt({name: "AES-CTR", length: 128}, key, data) // No counter
        }).to.throw('Counter must be exactly 16 bytes')
    })

    it("should throw with invalid counter", () => {
        expect(() => {
            aes.encrypt({name: "AES-CTR", counter: bad_iv, length: 128}, key, new Uint8Array())
        }).to.throw('Counter must be exactly 16 bytes')
    })

    it("should throw with length value", () => {
        expect(() => {
            aes.encrypt({name: "AES-CTR", counter: good_iv, length: 0}, key, new Uint8Array())
        }).to.throw('Length must be non zero and less than or equal to 128')
    })

    it('should return an ArrayBuffer', () => {
        aes.encrypt({name: "AES-CTR", counter: good_iv, length: 128}, key, data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a valid encryption', () => {
        Buffer.from(aes.encrypt({name: "AES-CTR", counter: good_iv, length: 128}, key, data))
        .should.eql(Buffer.from(signature.buffer))
    })
  }) // encrypt

/**
 * decrypt
 */
  describe('decrypt', () => {
    let aes, key, data, signature
    before(() => {
        aes = new AES_CTR({ name: "AES-CTR", length: 256 })
        key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CTR",
                ext: true,
            },
            {
                name: "AES-CTR",
            },
            true,
            ["encrypt", "decrypt"]
        )
        data = new Uint8Array([
          105, 17, 182, 253, 106, 236, 160, 39, 22, 23, 4, 230, 196, 
          158, 208, 79, 149, 225, 178, 37, 160, 63])
        signature = new TextEncoder().encode('Encoded with WebCrypto')
    })

    it("should throw with empty counter", () => {
        expect(() => {
            aes.decrypt({name: "AES-CTR", length: 128}, key, new Uint8Array()) // No counter
        }).to.throw('Counter must be exactly 16 bytes')
    })

    it("should throw with invalid counter", () => {
        expect(() => {
            aes.decrypt({name: "AES-CTR", counter: bad_iv, length: 128}, key, new Uint8Array())
        }).to.throw('Counter must be exactly 16 bytes')
    })

    it("should throw with invalid length value", () => {
        expect(() => {
            aes.decrypt({name: "AES-CTR", counter: good_iv, length: 1000}, key, new Uint8Array())
        }).to.throw('Length must be non zero and less than or equal to 128')
    })

    it('should return an ArrayBuffer', () => {
        aes.decrypt({name: "AES-CTR", counter: good_iv, length: 128}, key, data).should.be.instanceof(ArrayBuffer)
    })

    it('should return a valid decryption', () => {
        Buffer.from(aes.decrypt({name: "AES-CTR", counter: good_iv, length: 128}, key, data))
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
            name: "AES-CTR",
            length: 256,
        }
        aes = new AES_CTR(alg)
        return Promise.resolve()
        .then(() => cryptoKey = aes.generateKey(alg, true, ["encrypt", "decrypt"]))
    })

    it('should throw with invalid usages', () => {
        expect(() => {
            aes.generateKey(alg, true, ['encrypt', 'decrypt', 'wrong'])
        }).to.throw('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
    })

    it('should throw with invalid parameter length', () => {
        expect(() => {
            aes.generateKey({name:"AES-CTR", length:100}, true, ['encrypt', 'decrypt'])
        }).to.throw('Member length must be 128, 192, or 256.')
    })

    it('should return CryptoKey', () => {
        cryptoKey.should.be.instanceof(CryptoKey)
    })

    it('should be a secret key type', () => {
        cryptoKey.type.should.equal('secret')
    })

    it('should have AES_CTR type for algorithm', () => {
        cryptoKey.algorithm.should.instanceof(AES_CTR)
    })

    it('should set algorithm name', () => {
        cryptoKey.algorithm.name
        .should.equal('AES-CTR')
    })

    it('should set key as extractable', () => {
        cryptoKey.extractable.should.equal(true)
    })

    it('should set key usages', () => {
        cryptoKey.usages.should.eql(['encrypt','decrypt'])
    })

    it('should have correct length key handle', () => {
        cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length / 8)
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
        aes = new AES_CTR({ name: "AES-CTR", length: 256 })
    })

    it('should throw with invalid usages', () => {
        expect(() => {
            aes.importKey('raw', new Uint8Array([1,2,3,4]), {name:"AES-CTR"} , true, ['encrypt', 'decrypt', 'wrong'])
        }).to.throw('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
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
                name: "AES-CTR",
                length: 256,
            }
            aes = new AES_CTR(alg)
            raw = new Uint8Array([
                99, 76, 237, 223, 177, 224, 59, 31, 129, 99,
                180, 144, 141, 133, 102, 174, 168, 79, 144,
                238, 56, 34, 45, 137, 113, 191, 114, 201,
                213, 3, 61, 241])
            return Promise.resolve()
            .then(() => cryptoKey = aes.importKey("raw", raw, {name:"AES-CTR"}, true, ["encrypt", "decrypt"]))
        })

        it('should expect a suitable raw length', () => {
            expect(() => {
                aes.importKey('raw', new Uint8Array([1,2,3,4]), {name:"AES-CTR"} , true, ['encrypt','decrypt'])
            }).to.throw('Length of data bits must be 128, 192 or 256.')
        })

        it('should be a secret key type', () => {
            cryptoKey.type.should.equal('secret')
        })

        it('should have AES_CTR type for algorithm', () => {
            cryptoKey.algorithm.should.instanceof(AES_CTR)
        })

        it('should set algorithm name', () => {
            cryptoKey.algorithm.name
            .should.equal('AES-CTR')
        })

        it('should set key as extractable', () => {
            cryptoKey.extractable.should.equal(true)
        })

        it('should set key usages', () => {
            cryptoKey.usages.should.eql(['encrypt','decrypt'])
        })

        it('should have correct length key handle', () => {
            cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length / 8)
        })
    })//raw

    describe('with "jwk" format', () => {
        let alg, aes, key, cryptoKey

        before(() => {
            alg = {
                name: "AES-CTR",
                length: 256,
            }
            aes = new AES_CTR(alg)
            key = {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CTR",
                ext: true,
            }
            return Promise.resolve()
            .then(() => cryptoKey = aes.importKey("jwk", key, {name:"AES-CTR"}, true, ["encrypt", "decrypt"]))
        })

        it('should expect a suitable jwk format', () => {
            expect(() => {
                aes.importKey('jwk', "Incorrect", {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('Invalid jwk format')
        })

        it('should expect correct kty format', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "WRONG",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A256CTR",
                    ext: true,
                }, {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('kty property must be "oct"')
        })

        it('should expect data in k property', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    alg: "A256CTR",
                    ext: true,
                }, {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('k property must not be empty')
        })

        it('should expect A128CTR when data length is 16', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "c7WsUB6msAgIdDxTnT13Yw",
                    alg: "A256CTR",
                    ext: true,
                }, {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('Algorithm "A128CTR" must be 128 bits in length')
        })

        it('should expect A192CTR when data length is 24', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "c7WsUB6msAgIdDxTnT13YwY7SQjYVmrq",
                    alg: "A256CTR",
                    ext: true,
                }, {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('Algorithm "A192CTR" must be 192 bits in length')
        })

        it('should expect A256CTR when data length is 32', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A192CTR",
                    ext: true,
                }, {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('Algorithm "A256CTR" must be 256 bits in length')
        })

        it('should expect mismatched length when k is not appropriate base64url', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37",
                    alg: "A256CTR",
                    ext: true,
                }, {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('Algorithm and data length mismatch')
        })

        it('should expect correct value when "use" field is used', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A256CTR",
                    use: "WRONG",
                    ext: true,
                }, {name:"AES-CTR"} , false, ['encrypt','decrypt'])
            }).to.throw('Key use must be "enc"')
        })

        it('should expect valid key operations', () => {
            expect(() => {
                aes.importKey('jwk', key, {name:"AES-CTR"} , false, ['encrypt','decrypt','WRONG'])
            }).to.throw('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
        })

        it('should expect non extractable to not be extractable', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A256CTR",
                    ext: false,
                }, {name:"AES-CTR"} , true, ['encrypt','decrypt'])
            }).to.throw('Cannot be extractable when "ext" is set to false')
        })

        it('should be a secret key type', () => {
            cryptoKey.type.should.equal('secret')
        })

        it('should have AES_CTR type for algorithm', () => {
            cryptoKey.algorithm.should.instanceof(AES_CTR)
        })

        it('should set algorithm name', () => {
            cryptoKey.algorithm.name
            .should.equal('AES-CTR')
        })

        it('should set key as extractable', () => {
            cryptoKey.extractable.should.equal(true)
        })

        it('should set key usages', () => {
            cryptoKey.usages.should.eql(['encrypt','decrypt'])
        })

        it('should have correct length key handle', () => {
            cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length / 8)
        })
    })//jwk
  })//importKey

/**
 * exportKey
 */
  describe('exportKey', () => {
    let aes

    before(() => {
        aes = new AES_CTR({ name: "AES-CTR", length: 256 })
    })

    it('should have a valid handle in the key', () => {
        expect(() => {
            aes.exportKey('raw', {})
        }).to.throw('Missing key material')
    })

    it('should expect only "raw" or "jwk" formats', () => {
        expect(() => {
            aes.exportKey('WRONG',{handle:"Something"})
        }).to.throw('WRONG is not a supported key format')
    })

    describe('with "raw" format', () => {
        let alg, aes, key, raw, exportedFromChrome

        before(() => {
            alg = {
                name: "AES-CTR",
                length: 256,
            }
            aes = new AES_CTR(alg)
            key = aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CTR",
                ext: true
            }, {name:"AES-CTR"}, true, ["encrypt", "decrypt"])
            raw = aes.exportKey("raw",key)
            exportedFromChrome = new Uint8Array([
                99, 76, 237, 223, 177, 224, 59, 31, 129, 99, 180, 144, 141, 
                133, 102, 174, 168, 79, 144, 238, 56, 34, 45, 137, 113, 191, 
                114, 201, 213, 3, 61, 241])
        })

        it('should return a valid object', () => {
            raw.should.instanceof(Object)
        })

        it('should be the same as the Chrome exported key' , () => {
            Buffer.from(aes.exportKey("raw",key))
            .should.eql(Buffer.from(exportedFromChrome))
        })
    })//raw

    describe('with "jwk" format', () => {
        let alg, aes, key, jwk

        before(() => {
            alg = {
                name: "AES-CTR",
                length: 256,
            }
            aes = new AES_CTR(alg)
            key = aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CTR",
                ext: true
            }, {name:"AES-CTR"}, true, ["encrypt", "decrypt"])
            jwk = aes.exportKey("jwk",key)
        })

        it('should return a valid object', () => {
            jwk.should.instanceof(Object)
        })

        it('should expect correct kty field', () => {
            jwk.kty.should.eql("oct")
        })

        it('should expect A128CTR when data length is 16', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13Yw",
                alg: "A128CTR",
                ext: true
            }, {name:"AES-CTR"}, true,["encrypt", "decrypt"])).alg.should.eql("A128CTR")
        })

        it('should expect A192CTR when data length is 24', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13YwY7SQjYVmrq",
                alg: "A192CTR",
                ext: true
            }, {name:"AES-CTR"}, true, ["encrypt", "decrypt"])).alg.should.eql("A192CTR")
        })

        it('should expect A256CTR when data length is 32', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256CTR",
                ext: true
            }, {name:"AES-CTR"}, true, ["encrypt", "decrypt"])).alg.should.eql("A256CTR")
        })
    })//jwk
  })//exportKey

})
