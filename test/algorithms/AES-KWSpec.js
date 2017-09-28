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
const AES_KW = require('../../src/algorithms/AES-KW')
const AES_GCM = require('../../src/algorithms/AES-GCM')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')
const CurrentlyNotSupportedError = require('../../src/errors/CurrentlyNotSupportedError')

/**
 * Test code
 */
const good_iv =  Buffer.from([ 220, 29, 37, 164, 41, 84, 153, 197, 157, 122, 156, 254, 196, 161, 114, 74 ])
const bad_iv = new Array() // (2^64 - 1) max size can never occur, as length of array is bounded by 2^32

/**
 * Tests
 */
describe('AES_KW', () => {
  /**
   * dictionaries getter
   */
  describe.skip('dictionaries getter', () => {
    it('should return an array', () => {
      AES_KW.dictionaries.should.eql([
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
      AES_KW.members.publicExponent.should.equal('BufferSource')
    })
  })

  /**
   * wrapKey
   */
  describe('wrapKey', () => {
    let aes, key, data, signature

    before(() => {
        aes = new AES_KW({ name: "AES-KW", length: 256 })
        key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256KW",
                ext: true,
            },
            {
                name: "AES-KW",
            },
            true,
            ["wrapKey", "unwrapKey"]
        )
        signature = new Uint8Array([
            63, 180, 233, 152, 186, 3, 20, 59, 64, 210, 44, 117, 189, 
            178, 116, 253, 244, 208, 240, 194, 57, 201, 96, 118, 236, 
            78, 183, 171, 194, 117, 62, 142, 167, 21, 169, 255, 111, 
            227, 86, 199])
    })

    it('should return an ArrayBuffer', () => {
        aes.wrapKey("raw",key,key,{ name: "AES-KW" }).should.be.instanceof(ArrayBuffer)
    })

    it('should return a valid wrapped key object', () => {
        Buffer.from(aes.wrapKey("raw",key,key,{ name: "AES-KW" }))
        .should.eql(Buffer.from(signature.buffer))
    })

    it('should fail with invalid key length', () => {
        expect(() => {
            aes.wrapKey("raw",Buffer.from("invalid"),key,{name:"AES-KW"})
        }).to.throw('Invalid key length. Must be multiple of 8.')
    })
  }) // wrapKey

/**
 * unwrapKey
 */
  describe('unwrapKey', () => {
    let aes, key, data
    before(() => {
        aes = new AES_KW({ name: "AES-KW", length: 256 })
        key = aes.importKey(
            "jwk",
            {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256KW",
                ext: true,
            },
            {
                name: "AES-KW",
            },
            true,
            ["wrapKey", "unwrapKey"]
        )
        data = new Uint8Array([
            63, 180, 233, 152, 186, 3, 20, 59, 64, 210, 44, 117, 189, 
            178, 116, 253, 244, 208, 240, 194, 57, 201, 96, 118, 236, 
            78, 183, 171, 194, 117, 62, 142, 167, 21, 169, 255, 111, 
            227, 86, 199])
    })

    it('should return an Array', () => {
        aes.unwrapKey( 
            "raw",
            data,
            key,
            { name: "AES-KW" },
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["wrapKey","unwrapKey"]
         ).should.be.instanceof(Array)
    })
  }) // unwrapKey

/**
 * generateKey
 */
  describe('generateKey', () => {
    let alg, aes, cryptoKey

    before(() => {
        alg = {
            name: "AES-KW",
            length: 256,
        }
        aes = new AES_KW(alg)
        return Promise.resolve()
        .then(() => cryptoKey = aes.generateKey(alg, true, ["wrapKey", "unwrapKey"]))
    })

    it('should throw with invalid usages', () => {
        expect(() => {
            aes.generateKey(alg, true, ['wrapKey', 'unwrapKey', 'wrong'])
        }).to.throw('Key usages can only include "wrapKey" or "unwrapKey"')
    })

    it('should throw with invalid parameter length', () => {
        expect(() => {
            aes.generateKey({name:"AES-KW", length:100}, true, ['wrapKey', 'unwrapKey'])
        }).to.throw('Member length must be 128, 192, or 256.')
    })

    it('should return CryptoKey', () => {
        cryptoKey.should.be.instanceof(CryptoKey)
    })

    it('should be a secret key type', () => {
        cryptoKey.type.should.equal('secret')
    })

    it('should have AES_KW type for algorithm', () => {
        cryptoKey.algorithm.should.instanceof(AES_KW)
    })

    it('should set algorithm name', () => {
        cryptoKey.algorithm.name
        .should.equal('AES-KW')
    })

    it('should set key as extractable', () => {
        cryptoKey.extractable.should.equal(true)
    })

    it('should set key usages', () => {
        cryptoKey.usages.should.eql(['wrapKey','unwrapKey'])
    })

    it('should have correct length key handle', () => {
        cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length / 8)
    })

    it('should generate a random handle each time', () => {
        cryptoKey.handle.should.not.equal(
            aes.generateKey(alg, true, ['wrapKey', 'unwrapKey']).handle
        )
    })
  })//generateKey

/**
 * importKey
 */
  describe('importKey', () => {
    let aes

    before(() => {
        aes = new AES_KW({ name: "AES-KW", length: 256 })
    })

    it('should throw with invalid usages', () => {
        expect(() => {
            aes.importKey('raw', new Uint8Array([1,2,3,4]), {name:"AES-KW"} , true, ['wrapKey', 'unwrapKey', 'wrong'])
        }).to.throw('Key usages can only include "wrapKey" or "unwrapKey"')
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
                name: "AES-KW",
                length: 256,
            }
            aes = new AES_KW(alg)
            raw = new Uint8Array([
                99, 76, 237, 223, 177, 224, 59, 31, 129, 99,
                180, 144, 141, 133, 102, 174, 168, 79, 144,
                238, 56, 34, 45, 137, 113, 191, 114, 201,
                213, 3, 61, 241])
            return Promise.resolve()
            .then(() => cryptoKey = aes.importKey("raw", raw, {name:"AES-KW"}, true, ["wrapKey","unwrapKey"]))
        })

        it('should expect a suitable raw length', () => {
            expect(() => {
                aes.importKey('raw', new Uint8Array([1,2,3,4]), {name:"AES-KW"} , true, ['wrapKey','unwrapKey'])
            }).to.throw('Length of data bits must be 128, 192 or 256.')
        })

        it('should be a secret key type', () => {
            cryptoKey.type.should.equal('secret')
        })

        it('should have AES_KW type for algorithm', () => {
            cryptoKey.algorithm.should.instanceof(AES_KW)
        })

        it('should set algorithm name', () => {
            cryptoKey.algorithm.name
            .should.equal('AES-KW')
        })

        it('should set key as extractable', () => {
            cryptoKey.extractable.should.equal(true)
        })

        it('should set key usages', () => {
            cryptoKey.usages.should.eql(['wrapKey','unwrapKey'])
        })

        it('should have correct length key handle', () => {
            cryptoKey.handle.length.should.equal(cryptoKey.algorithm.length / 8)
        })
    })//raw

    describe('with "jwk" format', () => {
        let alg, aes, key, cryptoKey

        before(() => {
            alg = {
                name: "AES-KW",
                length: 256,
            }
            aes = new AES_KW(alg)
            key = {
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256KW",
                ext: true,
            }
            return Promise.resolve()
            .then(() => cryptoKey = aes.importKey("jwk", key, {name:"AES-KW"}, true, ["wrapKey","unwrapKey"]))
        })

        it('should expect a suitable jwk format', () => {
            expect(() => {
                aes.importKey('jwk', "Incorrect", {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('Invalid jwk format')
        })

        it('should expect correct kty format', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "WRONG",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A256KW",
                    ext: true,
                }, {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('kty property must be "oct"')
        })

        it('should expect data in k property', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    alg: "A256KW",
                    ext: true,
                }, {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('k property must not be empty')
        })

        it('should expect A128KW when data length is 16', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "c7WsUB6msAgIdDxTnT13Yw",
                    alg: "A256KW",
                    ext: true,
                }, {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('Algorithm "A128KW" must be 128 bits in length')
        })

        it('should expect A192KW when data length is 24', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "c7WsUB6msAgIdDxTnT13YwY7SQjYVmrq",
                    alg: "A256KW",
                    ext: true,
                }, {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('Algorithm "A192KW" must be 192 bits in length')
        })

        it('should expect A256KW when data length is 32', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A192KW",
                    ext: true,
                }, {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('Algorithm "A256KW" must be 256 bits in length')
        })

        it('should expect mismatched length when k is not appropriate base64url', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37",
                    alg: "A256KW",
                    ext: true,
                }, {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('Algorithm and data length mismatch')
        })

        it('should expect correct value when "use" field is used', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A256KW",
                    use: "WRONG",
                    ext: true,
                }, {name:"AES-KW"} , false, ["wrapKey","unwrapKey"])
            }).to.throw('Key use must be "enc"')
        })

        it('should expect valid key operations', () => {
            expect(() => {
                aes.importKey('jwk', key, {name:"AES-KW"} , false, ["wrapKey","unwrapKey",'WRONG'])
            }).to.throw('Key usages can only include "wrapKey" or "unwrapKey"')
        })

        it('should expect non extractable to not be extractable', () => {
            expect(() => {
                aes.importKey('jwk',{
                    kty: "oct",
                    k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                    alg: "A256KW",
                    ext: false,
                }, {name:"AES-KW"} , true, ["wrapKey","unwrapKey"])
            }).to.throw('Cannot be extractable when "ext" is set to false')
        })

        it('should be a secret key type', () => {
            cryptoKey.type.should.equal('secret')
        })

        it('should have AES_KW type for algorithm', () => {
            cryptoKey.algorithm.should.instanceof(AES_KW)
        })

        it('should set algorithm name', () => {
            cryptoKey.algorithm.name
            .should.equal('AES-KW')
        })

        it('should set key as extractable', () => {
            cryptoKey.extractable.should.equal(true)
        })

        it('should set key usages', () => {
            cryptoKey.usages.should.eql(["wrapKey","unwrapKey"])
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
        aes = new AES_KW({ name: "AES-KW", length: 256 })
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
        let alg, aes, key, raw

        before(() => {
            alg = {
                name: "AES-KW",
                length: 256,
            }
            aes = new AES_KW(alg)
            key = aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256KW",
                ext: true
            }, {name:"AES-KW"}, true, ["wrapKey","unwrapKey"])
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
                name: "AES-KW",
                length: 256,
            }
            aes = new AES_KW(alg)
            key = aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256KW",
                ext: true
            }, {name:"AES-KW"}, true, ["wrapKey","unwrapKey"])
            jwk = aes.exportKey("jwk",key)
        })

        it('should return a valid object', () => {
            jwk.should.instanceof(Object)
        })

        it('should expect correct kty field', () => {
            jwk.kty.should.eql("oct")
        })

        it('should expect A128KW when data length is 16', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13Yw",
                alg: "A128KW",
                ext: true
            }, {name:"AES-KW"}, true,["wrapKey","unwrapKey"])).alg.should.eql("A128KW")
        })

        it('should expect A192KW when data length is 24', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "c7WsUB6msAgIdDxTnT13YwY7SQjYVmrq",
                alg: "A192KW",
                ext: true
            }, {name:"AES-KW"}, true, ["wrapKey","unwrapKey"])).alg.should.eql("A192KW")
        })

        it('should expect A256KW when data length is 32', () => {
            aes.exportKey("jwk",aes.importKey("jwk",{
                kty: "oct",
                k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
                alg: "A256KW",
                ext: true
            }, {name:"AES-KW"}, true, ["wrapKey","unwrapKey"])).alg.should.eql("A256KW")
        })
    })//jwk
  })//exportKey

})
