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
const crypto = require('../src')
const CryptoKey = require('../src/CryptoKey')
const CryptoKeyPair = require('../src/CryptoKeyPair')
const {ab2str,str2ab,ab2buf,buf2ab} = require('../src/encodings')

/**
 * RSA Key Pair
 */
const RsaPrivateKey =
`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAiEJoO1tBT1Yc9jdYWI5JUkMnOlFD+weoi1rkxsWvZoBRJJGi
fjrdmIn/5xOaaW38Cg535lo6NEorsVsq7V6zGan2QCT1TRCb7vJq4UIEq6tL5uB0
BZMyByKBYDKVGAinXYd502nJ1T7sbZQnSjZFC3HgDvrqb/4bDIbO0+sAiaTumt+2
uyIYcGYBuIfTi8vmElz2ngUFh+8K/uQyH7YjrOrg6ThOldh8IVzaOSA7LAb/DjyC
+H44F/J24qMRLGuWK53gz+2RazSBotiNUsGoxdZv30Sud3Yfbz9ZjSXxPWpRnG6m
ZAZW76oSbn8FvTSTWrf0iU6MyNkv/QuAjF+1BQIDAQABAoIBAHb3G8/vDad59NFX
Yu/2Urfa363/882BUztQQXv2bvycPbwi1u9E7+JVYjLbH667ExmopjBdSIIM2/b+
NQ2H5/EZPmGkovME9E/8ISrInBFR/nP2NfYEHOKz0qctopSYQZ/cP5ZAv7JKPNwz
RNZ7aW7jno8VrYfYIL+gF4ZYoGCLdIdw2rFaobZFGtUQ1ASpuBIS3NAQjxQLTdlz
jUXCqqE02VKVW6Chr/ZPDnsjDmVxZjY5+vLoZRyS4jWBR64fgVrA+FoCFqtbKh5X
ZCGUSRhGYs06XLlnjLn91ftgO6Di3FbQ2d4nrMRkD8ciOPv1iao429wKThiChTge
0DRF5SECgYEAvblqHOYDjdRTPV2rumoWKPzREhebi0ljKeMBFPvqVBM/IvOhqpVa
cBsDCNGHwkOo3lX+M+c8y381ZR66pJb5QpF7qfIjlOQEYQfLc31HErYcHiPtKSNj
L4HP5kAoZT4ILFZlfnVJP8oZ/S+BKO27juMwDVUk/wlI2CiN0a1oPWkCgYEAt9vB
+yjoWydrBXy5q4m0pMcTm9FZum9kahCXx/0QjYPLjxwX6+d8Tc1Y1/VROtQDAIxu
yMZxkboQ0L8uXtVQCjVz8hG1UDeqzISxLyTVP+JtD6yijhyrtQdgtokgAFzBHpYa
MKgr8tARtojF5EyWPTQJpBSI2+tl0GgwEOa3Gz0CgYB65SQLXCNpN+RDl+2pbxaz
rjBvm8Mx0nPdqiIFSblchKsdJNvP97cBbz3j9HYQLGuyudlUHbGPz/LycZlNDE6i
BEMqrqLFy33arIXpZXkocbZ8/6CcSUPyfhABggWoryn0LnLIG4k7PNrg2mi77mLU
B+4UdNbmLUl2W66h58XiIQKBgDG6kMccE2zERqAfUiDhiCihZ95XS4uvoVtGzabb
/eQo55/3m0jFPcvVZNhUk/nzajR1x2kqs4EU8INlkmc4DwQT3R52R7JAvEPBCCOW
NM+osJLywKzreE3ohvIYOL2gWOOq+b57Xhe4y3GxoMTVKjW3o3vryfChxNIPvCB2
JsSJAoGBAJV3gcwgFgAA6t8m7g4YStDKANJngttdfHZC1IhGFOtKPc/rneobgDCt
48gw9bQD8gy87laRb/hjm/0Az4bjtDDOkKY5yhCUtipnpx4FR12nGRmMfRGedLJh
rrdlkni8537vUl2rwiG3U3LTi9vHMIbBQek5rxlbc8jS8ejGUFdc
-----END RSA PRIVATE KEY-----`

const RsaPublicKey =
`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiEJoO1tBT1Yc9jdYWI5J
UkMnOlFD+weoi1rkxsWvZoBRJJGifjrdmIn/5xOaaW38Cg535lo6NEorsVsq7V6z
Gan2QCT1TRCb7vJq4UIEq6tL5uB0BZMyByKBYDKVGAinXYd502nJ1T7sbZQnSjZF
C3HgDvrqb/4bDIbO0+sAiaTumt+2uyIYcGYBuIfTi8vmElz2ngUFh+8K/uQyH7Yj
rOrg6ThOldh8IVzaOSA7LAb/DjyC+H44F/J24qMRLGuWK53gz+2RazSBotiNUsGo
xdZv30Sud3Yfbz9ZjSXxPWpRnG6mZAZW76oSbn8FvTSTWrf0iU6MyNkv/QuAjF+1
BQIDAQAB
-----END PUBLIC KEY-----`

/**
 * Tests
 */
describe('SubtleCrypto', () => {

  /**
   * encrypt
   */
  describe('encrypt', () => {
    it('should return a Promise')
  })

  /**
   * decrypt
   */
  describe('decrypt', () => {
    it('should return a Promise')
  })

  /**
   * sign
   */
  describe('sign', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        let privateKey = new CryptoKey({})
        let data = new ArrayBuffer()

        promise = crypto.subtle.sign(algorithm, privateKey, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with mismatched algorithm name', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }
        let privateKey = new CryptoKey({ algorithm: { name: 'RSA-PSS' } })
        let data = new ArrayBuffer()

        promise = crypto.subtle.sign(algorithm, privateKey, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Algorithm does not match key')
      })
    })

    describe('with invalid usages', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }

        let privateKey = new CryptoKey({
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
          usages: ['verify']
        })

        let data = new ArrayBuffer()

        promise = crypto.subtle.sign(algorithm, privateKey, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Key usages must include "sign"')
      })
    })

    describe('with valid arguments', () => {
      let promise, result, error

      beforeEach((done) => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }

        let privateKey = new CryptoKey({
          type: 'private',
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
          extractable: false,
          usages: ['sign'],
          handle: RsaPrivateKey
        })

        let data = str2ab('data')

        promise = crypto.subtle
          .sign(algorithm, privateKey, data)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(ArrayBuffer)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        let publicKey = new CryptoKey({algorithm})
        let signature = new ArrayBuffer()
        let data = new ArrayBuffer()

        promise = crypto.subtle.verify(algorithm, publicKey, signature, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with mismatched algorithm name', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }
        let publicKey = new CryptoKey({ algorithm: { name: 'RSA-PSS' } })
        let signature = new ArrayBuffer()
        let data = new ArrayBuffer()

        promise = crypto.subtle.verify(algorithm, publicKey, signature, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Algorithm does not match key')
      })
    })

    describe('with invalid usages', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }
        let publicKey = new CryptoKey({
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
          usages: ['sign']
        })
        let signature = new ArrayBuffer()
        let data = new ArrayBuffer()

        promise = crypto.subtle.verify(algorithm, publicKey, signature, data)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('Key usages must include "verify"')
      })
    })

    describe('with valid arguments', () => {
      let signature = buf2ab(new Buffer('X68EtkKcwZqcySv/NU6hucJg9b/uHojiOzQ2uttIH9V9kS5ACmTnsPY5Kk708foNACHcNrvAk2S8szAJWbK8RJPW1So4OyArqRjnTyjADpriLjCEIUZZBT6Igpeddv5unOZnrmLPXNePQLVGsOXcW6xmy7kZrSbXmsTJet6dvfku0AM0DNjpdZonKIewjZf6ALSkNiskpo8Fm14GRb3c9ZytQziD5mWHNvuUi4ZV3SiIzs7LBzUnmcB94E67fw7vhOP/OnYmVB5cM+ANTKmjIHJgWgXcUM6SrHMs8oy0ENvKQOMWUdbX4qetvBMOR1/3GV5oUWIVqj0wlDqH0wMqCA==', 'base64'))

      let promise, result, error

      beforeEach((done) => {
        let algorithm = { name: 'RSASSA-PKCS1-v1_5' }

        let publicKey = new CryptoKey({
          type: 'public',
          algorithm: { name: 'RSASSA-PKCS1-v1_5' },
          extractable: false,
          usages: ['verify'],
          handle: RsaPublicKey
        })

        let data = str2ab('data')

        promise = crypto.subtle
          .verify(algorithm, publicKey, signature, data)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.equal(true)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * digest
   */
  describe('digest', () => {
    it('should return a Promise')
  })

  /**
   * generateKey
   */
  describe('generateKey', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let algorithm = { name: 'BAD-ALGORITHM' }
        promise = crypto.subtle.generateKey(algorithm, false, ['sign', 'verify'])
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    // IS THERE ANY WAY TO TEST THIS WITHOUT SPIES/STUBS?
    // IF THE UNDERLYING ALGORITHMS ARE DOING THE RIGHT THING
    // IT WILL ERROR BEFORE EVER GETTING HERE
    describe('with invalid CryptoKey usages', () => {
      it('should return a promise')
      it('should reject the promise')
    })

    describe('with invalid CryptoKeyPair usages', () => {
      it('should return a promise')
      it('should reject the promise')
    })

    describe('with valid arguments', () => {
      let promise, result, error

      beforeEach((done) => {
        let algorithm = {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 1024,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: 'SHA-256' }
        }

        let extractable = false
        let usages = ['sign', 'verify']

        promise = crypto.subtle
          .generateKey(algorithm, extractable, usages)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(CryptoKeyPair)
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })
    })
  })

  /**
   * deriveKey
   */
  describe('deriveKey', () => {
    it('should return a Promise')
  })

  /**
   * deriveBits
   */
  describe('deriveBits', () => {
    it('should return a Promise')
  })

  /**
   * importKey
   */
  describe.only('importKey', () => {
    describe('with invalid algorithm', () => {
      let promise, error

      beforeEach(() => {
        let format = 'jwk'
        let key = {}
        let algorithm = { name: 'BAD-ALGORITHM' }
        let extractable = false
        let usages = ['verify']

        promise = crypto.subtle.importKey('jwk', key, algorithm, extractable, usages)
        promise.catch(err => error = err)
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should reject the promise', () => {
        error.should.be.instanceof(Error)
        error.message.should.include('is not a supported algorithm')
      })
    })

    describe('with raw format', () => {})
    describe('with pkcs8 format', () => {})
    describe('with spki format', () => {})
    describe('with jwk format', () => {})
    describe('with invalid resulting usages', () => {})

    describe('with valid arguments', () => {
      let promise, result, error

      beforeEach((done) => {
        let key = {
          kty: "RSA",
          e: "AQAB",
          n: "vGO3eU16ag9zRkJ4AK8ZUZrjbtp5xWK0LyFMNT8933evJoHeczexMUzSiXaLrEFSyQZortk81zJH3y41MBO_UFDO_X0crAquNrkjZDrf9Scc5-MdxlWU2Jl7Gc4Z18AC9aNibWVmXhgvHYkEoFdLCFG-2Sq-qIyW4KFkjan05IE",
          alg: "RS256",
          ext: true
        }

        let algorithm = {
          name: 'RSASSA-PKCS1-v1_5',
          hash: { name: 'SHA-256' }
        }

        let extractable = true
        let usages = ['sign', 'verify', 'nope']

        promise = crypto.subtle
          .importKey('jwk', key, algorithm, extractable, usages)
          .then(res => {
            result = res
            done()
          })
          .catch(err => {
            error = err
            done()
          })
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve the promise', () => {
        result.should.be.instanceof(CryptoKey)
      })

      it('should set extractable', () => {
        result.extractable.should.equal(true)
      })

      it('should normalize key usages', () => {
        result.usages.should.eql(['sign', 'verify'])
      })

      it('should not reject the promise', () => {
        expect(error).to.be.undefined
      })

    })
  })

  /**
   * exportKey
   */
  describe('exportKey', () => {
    it('should return a Promise')
  })

  /**
   * wrapKey
   */
  describe('wrapKey', () => {
    it('should return a Promise')
  })

  /**
   * unwrapKey
   */
  describe('unwrapKey', () => {
    it('should return a Promise')
  })
})
