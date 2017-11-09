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
const {TextEncoder} = require('text-encoding')
const crypto = require('../../src')
const CryptoKey = require('../../src/keys/CryptoKey')
const CryptoKeyPair = require('../../src/keys/CryptoKeyPair')
const KeyAlgorithm = require('../../src/dictionaries/KeyAlgorithm')
const RsaKeyAlgorithm = require('../../src/dictionaries/RsaKeyAlgorithm')
const RsaHashedKeyAlgorithm = require('../../src/dictionaries/RsaHashedKeyAlgorithm')
const RSA_OAEP = require('../../src/algorithms/RSA-OAEP')
const DataError = require('../../src/errors/DataError')
const OperationError = require('../../src/errors/OperationError')
const NotSupportedError = require('../../src/errors/NotSupportedError')

/**
 * Code under test
 */
let Rsa = new RSA_OAEP({ name: "RSA-OAEP", hash: { name: 'SHA-1' } })
let RsaPrivateJwk = {
  "alg":"RSA-OAEP",
  "d":"OONqS6vhPhdw_a5PZ7e0dIQNk8k2x8S_4wdsGcw5LVKRnsm07IDSb6JgsSBrM16tpthXbdAqFp5Lbcuc8clkRN0RUlH5aBCuFHQDRit5c7hvhDKbR5Tjuu8i6ZfGNCXzU-oFeaPBAP6aiclmJZO0wyRvTYNtvRcjELix11MWfhxulAiMayEXG47AvLycBOim1hui28R3WYwH8Yfc7-BoXITjy8V9ViMRCU2cVnPtXQYnz27KAYFmV7wcAhWgB5T97abSVWwgk_ZIhjfieNjOLuG2veVuDOni-mzMjg_5DwWAtMkx2G9fysSaHJiarcb071BEIurD5uZ3EPKxSksE4Q",
  "dp":"YU25IwbEb_BVTCYkd01iVZQBCPrkHMEUt0SDkWuFHmOiIfaDgbnIy9euDffwNglJMTDuxmKsXqiOnnJ4Q4Vjxm3v4gKNGsvckhfTxbX9Y_XIyxXTASRCBUDpyGQ2JllgUT3IAMBC4H7sb6c-fuwrGqQurNGSIcrTng3v-jHoedE",
  "dq":"csjKDq30kz-zoTs9e4YMuZ_h4NmZy9b-X3-oLHsMmA_TU4D2_bWqVaN4j8zURKOutrkepnYzOgacN2oR9dBj_Z8PLyPIgM03EuuFU5InkzAQ-DnUzJQU6gH1RgaWiG2lswLDEHQc3-d2fohveFxM90zAjP0Dhe-BTbt07GpE9sU",
  "e":"AQAB",
  "ext":true,
  "key_ops":["decrypt"],
  "kty":"RSA",
  "n":"q6kM0z9Faa2BHYSakuzZKirz3o7dNG83nq3Yw5KC1FOUkQStDtYz8EMkYV99WfHMCaRA_q_WBjRVnweQawFtR4zwNcmEhU-fUEIZCZ17ArKoNOy45Ep8NVuYJG3-OyYHuwnz5xLIvW9GVk2UqAJKaLSatuT2utU6JKeLu-4C0cb4eYUGT_RT-qsTF_NSWyyzdHrZzp9FX7ly-UTZw3inyjZYp5Ps1Ka5HzByzCTHhs_tatzLwG0FgjS7msPmwzE9RZFr1-J9exvIqhCmhvj5LSIdFmm5MEXC_b47fYCqSCE81bBofD2Ee0k72qOA-JfKNhrNXoLzuR7_1Ig1xJ8Ahw",
  "p":"0ca0ebRJqK1jhNd9e0dRMrl5_cJhxMZAH3jyHNgC-vqSmFjobkNOwvUxzyf-kXLvrNCuJbkQqQHN87saSGunAHpDdFPV1lsymnemLJjsfMNy1Qf5yw6r277gz1mVDcgfJbP_4vcps0v-VmIgaBwtkPNJVTv-PjVAY3PAXpqwSjE",
  "q":"0XxDaEvgA5ECPsFMiqsuhWajiv8I-nzi3EUeq25Za0PR_9S7HF0TXxk84-EPmCU1WxeilFhL96--g4fmypBjVaszL-nP7Thq4MBBPM5cviPuUoQXmYVOtD1q8rmVmc0HbtuzM5fmBbSfGn9sLhu6DE1ymlabHjvn-FWuIWLcEDc",
  "qi":"W-VEZ0hgjSA4qFjAkfaBK58NAV9rY45MP4n2MauCSoR9uqjkrYJQm74774G8tILIsw72eKejfObh6mmZUSPvOKRn-femd7KCH6x54sdNExvP3kAbXDVH9NhxgEjNjpsPjoyKXJGGZrAwPV6sncgea-h79gRXKRFYhXSK2cIk6Xk"
}
let RsaPrivateCryptoKey = Rsa.importKey(
    "jwk",
    RsaPrivateJwk,
    {  
        name: "RSA-OAEP",
        hash: {name: "SHA-1"}, 
    },
    true,
    ["decrypt"]
  )
let RsaPublicJwk = {
  "alg":"RSA-OAEP",
  "e":"AQAB",
  "ext":true,
  "key_ops":["encrypt"],
  "kty":"RSA",
  "n":"q6kM0z9Faa2BHYSakuzZKirz3o7dNG83nq3Yw5KC1FOUkQStDtYz8EMkYV99WfHMCaRA_q_WBjRVnweQawFtR4zwNcmEhU-fUEIZCZ17ArKoNOy45Ep8NVuYJG3-OyYHuwnz5xLIvW9GVk2UqAJKaLSatuT2utU6JKeLu-4C0cb4eYUGT_RT-qsTF_NSWyyzdHrZzp9FX7ly-UTZw3inyjZYp5Ps1Ka5HzByzCTHhs_tatzLwG0FgjS7msPmwzE9RZFr1-J9exvIqhCmhvj5LSIdFmm5MEXC_b47fYCqSCE81bBofD2Ee0k72qOA-JfKNhrNXoLzuR7_1Ig1xJ8Ahw"
}
let RsaPublicCryptoKey = Rsa.importKey(
    "jwk", 
    RsaPublicJwk,
    {   
        name: "RSA-OAEP",
        hash: {name: "SHA-1"}, 
    },
    true,
    ["encrypt"]
  )
let RsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6kM0z9Faa2BHYSakuzZ
Kirz3o7dNG83nq3Yw5KC1FOUkQStDtYz8EMkYV99WfHMCaRA/q/WBjRVnweQawFt
R4zwNcmEhU+fUEIZCZ17ArKoNOy45Ep8NVuYJG3+OyYHuwnz5xLIvW9GVk2UqAJK
aLSatuT2utU6JKeLu+4C0cb4eYUGT/RT+qsTF/NSWyyzdHrZzp9FX7ly+UTZw3in
yjZYp5Ps1Ka5HzByzCTHhs/tatzLwG0FgjS7msPmwzE9RZFr1+J9exvIqhCmhvj5
LSIdFmm5MEXC/b47fYCqSCE81bBofD2Ee0k72qOA+JfKNhrNXoLzuR7/1Ig1xJ8A
hwIDAQAB
-----END PUBLIC KEY-----
`


/**
 * Tests
 */
describe('RSA_OAEP', () => {
  /**
   * dictionaries getter
   */
  describe.skip('dictionaries getter', () => {
    it('should return an array', () => {
      RSA_OAEP.dictionaries.should.eql([
        KeyAlgorithm,
        RsaKeyAlgorithm,
        RsaHashedKeyAlgorithm
      ])
    })
  })

  /**
   * members getter
   */
  describe.skip('members getter', () => {
    it('should return an object', () => {
      RSA_OAEP.members.publicExponent.should.equal('BufferSource')
      RSA_OAEP.members.hash.should.equal('HashAlgorithmIdentifier')
    })
  })

  /**
   * encrypt
   */
  describe('encrypt', () => {
    let alg, rsa, data, signature

    before(() => {
      alg = { name: "RSA-OAEP", hash: { name: 'SHA-1' } }
      rsa = new RSA_OAEP(alg)

      data = new TextEncoder().encode('signed with Chrome webcrypto')
    })

    it('should throw with non-private key', () => {
      expect(() => {
        rsa.encrypt(alg, RsaPrivateCryptoKey, new Uint8Array())
      }).to.throw('Encrypt requires a public key')
    })

    it('should return an ArrayBuffer', () => {
      rsa.encrypt(alg, RsaPublicCryptoKey, data).should.be.instanceof(ArrayBuffer)
    })
  })

  /**
   * decrypt
   */
  describe('decrypt', () => {
    let alg, rsa, data, signature

    before(() => {
      alg = { name: "RSA-OAEP", hash: { name: 'SHA-1' } }
      rsa = new RSA_OAEP(alg)

      data = new TextEncoder().encode('signed with Chrome webcrypto')

      signature = new Uint8Array([
        22,101,79,138,156,147,203,26,157,52,218,189,207,28,192,159,210,80,154,46,234,
        227,224,21,90,105,28,181,31,92,255,166,158,27,162,118,137,11,72,230,33,137,19,
        189,208,227,31,134,82,51,72,162,102,12,162,250,143,207,253,111,144,135,244,145,
        220,225,168,21,176,57,220,173,75,41,45,9,41,50,92,229,54,214,100,200,192,11,235,
        44,162,240,24,215,227,19,63,112,222,111,233,6,147,151,98,12,36,120,83,157,6,129,
        117,28,28,188,32,124,218,161,192,247,153,156,176,166,119,77,67,98,80,250,0,254,
        175,63,107,171,70,168,156,103,247,6,70,143,11,21,184,229,53,164,140,169,32,137,
        8,41,89,183,2,242,213,244,115,197,134,169,70,160,90,91,170,9,51,104,108,165,85,
        67,165,171,92,8,229,224,68,10,74,23,156,101,97,81,48,122,47,228,67,80,210,179,
        118,0,101,185,63,220,49,107,52,61,11,189,242,43,167,43,159,107,114,12,226,228,
        120,140,7,21,37,207,13,217,80,235,149,213,1,255,255,86,58,167,181,4,173,223,
        234,104,104,225,26,54,46,162,201,37,167,149
      ])
    })

    it('should throw with non-private key', () => {
      expect(() => {
        rsa.decrypt(alg, RsaPublicCryptoKey, new Uint8Array())
      }).to.throw('Decrypt requires a private key')
    })

    it('should return an ArrayBuffer', () => {
      rsa.decrypt(alg, RsaPrivateCryptoKey, signature).should.be.instanceof(ArrayBuffer)
    })

    it('should return a valid decryption', () => {
      Buffer.from(rsa.decrypt(alg, RsaPrivateCryptoKey, signature))
      .should.eql(Buffer.from(data.buffer))
    })
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    let alg, rsa, cryptoKeyPair

    before(() => {
      alg = { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
      rsa = new RSA_OAEP(alg)
      return Promise.resolve()
        .then(() => cryptoKeyPair = rsa.generateKey(
          {
            name: "RSA-OAEP",
            modulusLength: 1024, 
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}, 
          },
        true, 
        ["encrypt", "decrypt"]
      ))
    })

    it('should throw with invalid usages', () => {
      expect(() => {
        rsa.generateKey(alg, true, ['encrypt', 'decrypt', 'wrong'])
      }).to.throw('Key usages can only include "encrypt", "decrypt", "wrapKey" or "unwrapKey"')
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
        .should.be.instanceof(RSA_OAEP)
    })

    it('should set private key algorithm', () => {
      cryptoKeyPair.privateKey.algorithm
        .should.be.instanceof(RSA_OAEP)
    })

    it('should set public key algorithm name', () => {
      cryptoKeyPair.publicKey.algorithm.name
        .should.equal('RSA-OAEP')
    })

    it('should set private key algorithm name', () => {
      cryptoKeyPair.privateKey.algorithm.name
        .should.equal('RSA-OAEP')
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
      cryptoKeyPair.publicKey.usages.should.eql(['encrypt','wrapKey'])
    })

    it('should set private key usages', () => {
      cryptoKeyPair.privateKey.usages.should.eql(['decrypt','unwrapKey'])
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

          alg = new RSA_OAEP({
            name: 'RSA-OAEP',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['bad'])
          }).to.throw('Key usages can only include "decrypt" or "unwrapKey"')
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

          alg = new RSA_OAEP({
            name: 'RSA-OAEP',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw SyntaxError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['bad'])
          }).to.throw('Key usages can only include "encrypt" or "wrapKey"')
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

          alg = new RSA_OAEP({
            name: 'RSA-OAEP',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['encrypt'])
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

          alg = new RSA_OAEP({
            name: 'RSA-OAEP',
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
          })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', key, alg, false, ['encrypt'])
          }).to.throw('Key use must be "sig"')
        })
      })

      describe('RSA-OAEP key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RSA-OAEP",
            ext: true
          }

          alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" } })
          key = alg.importKey('jwk', jwk, alg, false, ['encrypt'])
        })

        it('should set SHA-1 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-1')
        })
      })

      describe('RSA-OAEP-256 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RSA-OAEP-256",
            ext: true
          }

          alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-256" }})
          key = alg.importKey('jwk', jwk, alg, false, ['encrypt'])
        })

        it('should set SHA-256 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-256')
        })
      })

      describe('RSA-OAEP-384 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RSA-OAEP-384",
            ext: true
          }

          alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-384" } })
          key = alg.importKey('jwk', jwk, alg, false, ['encrypt'])
        })

        it('should set SHA-384 hash', () => {
          key.algorithm.hash.name.should.equal('SHA-384')
        })
      })

      describe('RSA-OAEP-512 key alg', () => {
        let key, jwk, alg

        before(() => {
          jwk = {
            kty: "RSA",
            e: "AQAB",
            n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
            alg: "RSA-OAEP-512",
            ext: true
          }

          alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-512" } })
          key = alg.importKey('jwk', jwk, alg, false, ['encrypt'])
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
            alg: "WRONG",
            ext: true
          }

          alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" } })
        })

        it('should throw DataError', () => {
          expect(() => {
            alg.importKey('jwk', jwk, alg, false, ['encrypt'])
          }).to.throw('Currently \'WRONG\' is not a supported format. Please use \'RSA-OAEP\' in the interim.')
        })
      })

      describe('private RSA key', () => {
        let key, alg

        before(() => {
          alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" } })
          key = alg.importKey('jwk', RsaPrivateJwk, alg, false, ['decrypt'])
        })

        it('should define type', () => {
          key.type.should.equal('private')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RSA_OAEP)
        })

        it('should define extractable', () => {
          key.extractable.should.equal(false)
        })

        it('should define usages', () => {
          key.usages.should.eql(['decrypt'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN RSA PRIVATE KEY-----')
        })
      })

      describe('public RSA key', () => {
        let key, alg

        before(() => {
          alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" }  })
          key = alg.importKey('jwk', RsaPublicJwk, alg, false, ['encrypt'])
        })

        it('should define type', () => {
          key.type.should.equal('public')
        })

        it('should define algorithm', () => {
          key.algorithm.should.be.instanceof(RSA_OAEP)
        })

        it('should define extractable', () => {
          key.extractable.should.equal(true)
        })

        it('should define usages', () => {
          key.usages.should.eql(['encrypt'])
        })

        it('should define handle', () => {
          key.handle.should.contain('-----BEGIN PUBLIC KEY-----')
        })
      })
    })

    describe('with other format', () => {
      it('should throw NotSupportedError', () => {
        let alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" }  })

        let caller = () => {
          alg.importKey('WRONG', RsaPublicJwk, alg, false, ['decrypt'])
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
          let alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" } })
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
            usages: ['encrypt'],
            handle: RsaPublicKey
          })

          let alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" } })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RSA-OAEP"', () => {
          jwk.alg.should.equal('RSA-OAEP')
        })
      })

      describe('SHA-256 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-256' } },
            extractable: true,
            usages: ['encrypt'],
            handle: RsaPublicKey
          })

          let alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-256" } })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RSA-OAEP-256"', () => {
          jwk.alg.should.equal('RSA-OAEP-256')
        })
      })

      describe('SHA-384 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-384' } },
            extractable: true,
            usages: ['encrypt'],
            handle: RsaPublicKey
          })

          let alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-384" } })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RSA-OAEP-384"', () => {
          jwk.alg.should.equal('RSA-OAEP-384')
        })
      })

      describe('SHA-512 hash', () => {
        let jwk

        before(() => {
          let key = new CryptoKey({
            type: 'public',
            algorithm: { hash: { name: 'SHA-512' } },
            extractable: true,
            usages: ['encrypt'],
            handle: RsaPublicKey
          })

          let alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-512" } })
          jwk = alg.exportKey('jwk', key)
        })

        it('should set "alg" to "RSA-OAEP-512"', () => {
          jwk.alg.should.equal('RSA-OAEP-512')
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
          usages: ['encrypt'],
          handle: RsaPublicKey

        })

        let alg = new RSA_OAEP({ name: 'RSA-OAEP', hash: { name: "SHA-1" } })

        let caller = () => {
          alg.exportKey('WRONG', key)
        }

        expect(caller).to.throw(NotSupportedError)
        expect(caller).to.throw('is not a supported key format')
      })
    })
  })
})
